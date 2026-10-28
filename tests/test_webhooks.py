from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from portal.models import Base, WebhookDelivery, WebhookSubscription
from portal.routers.webhooks import validate_ssrf
from portal.webhooks.worker import sign_payload

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db():
    """Yield an async session backed by an in-memory SQLite database."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as session:
            async with session.begin():
                yield session
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Tests for Webhook Utilities
# ---------------------------------------------------------------------------


def test_sign_payload():
    secret = "whsec_test123"
    payload = '{"test": "data"}'
    timestamp = 1620000000

    signature = sign_payload(secret, payload, timestamp)
    # The signature should be a valid SHA-256 hex string (64 characters)
    assert len(signature) == 64
    assert isinstance(signature, str)


def test_validate_ssrf(monkeypatch):
    monkeypatch.setattr(
        "portal.routers.webhooks.socket.gethostbyname", lambda host: host if host[0].isdigit() else "93.184.216.34"
    )
    # Valid HTTPS external URL
    validate_ssrf("https://webhook.site/123")

    # HTTP is rejected (must use HTTPS)
    with pytest.raises(HTTPException) as exc:
        validate_ssrf("http://example.com/api/webhooks")
    assert exc.value.status_code == 400

    # Internal IPs (should fail)

    with pytest.raises(HTTPException) as exc:
        validate_ssrf("https://192.168.1.5")
    assert exc.value.status_code == 400

    with pytest.raises(HTTPException) as exc:
        validate_ssrf("https://10.0.0.1")
    assert exc.value.status_code == 400

    # Invalid URL structures
    with pytest.raises(HTTPException) as exc:
        validate_ssrf("not_a_url")
    assert exc.value.status_code == 400

    with pytest.raises(HTTPException) as exc:
        validate_ssrf("ftp://example.com")
    assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# Tests for Webhook Routes
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_create_webhook_idempotency_and_deduplication(db, monkeypatch):
    from portal.models import DeveloperAccount, Event, OAuthClient, OAuthToken, User
    from portal.routers.webhooks import WebhookCreate, create_webhook

    monkeypatch.setattr("portal.routers.webhooks.validate_ssrf", lambda url: None)

    user = User(email="dev@example.com", display_name="Dev User", is_active=True)
    db.add(user)
    await db.flush()

    event = Event(slug="dev-event", display_name="Dev Event")
    db.add(event)
    await db.flush()

    dev_account = DeveloperAccount(user_id=user.id, status="approved")
    db.add(dev_account)
    await db.flush()

    client = OAuthClient(
        developer_account_id=dev_account.id,
        client_id="client_test_123",
        name="Test App",
    )
    db.add(client)
    await db.flush()

    token = OAuthToken(
        client_id=client.id,
        user_id=user.id,
        event_id=event.id,
        scopes=["webhooks:manage"],
        access_token_hash="hash123",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(token)
    await db.flush()

    # 1. Create first webhook subscription
    req1 = WebhookCreate(
        target_url="https://client.example.com/webhook/",
        event_types=["booth.transcription.started"],
    )
    res1 = await create_webhook(req1, token=token, db=db)
    assert res1.id is not None
    assert res1.target_url == req1.target_url
    assert res1.event_types == ["booth.transcription.started"]
    assert res1.secret_key.startswith("whsec_")
    orig_id = res1.id
    orig_secret = res1.secret_key

    # 2. Call again with same target_url but updated event_types
    from fastapi import Response

    resp2 = Response()
    req2 = WebhookCreate(
        target_url="https://client.example.com/webhook/",
        event_types=["booth.transcription.started", "booth.transcription.stopped"],
    )
    res2 = await create_webhook(req2, response=resp2, token=token, db=db)
    assert resp2.status_code == 200
    assert res2.id == orig_id
    assert res2.secret_key == orig_secret
    assert set(res2.event_types) == {"booth.transcription.started", "booth.transcription.stopped"}

    # Verify only 1 row exists in DB
    all_subs = (await db.execute(select(WebhookSubscription))).scalars().all()
    assert len(all_subs) == 1

    # 3. Simulate legacy duplicate rows in DB (e.g. from prior bug)
    dup = WebhookSubscription(
        developer_account_id=dev_account.id,
        target_url="https://client.example.com/webhook/",
        event_types=["booth.transcription.started"],
        secret_key="whsec_duplicate",
        is_active=True,
    )
    db.add(dup)
    await db.flush()

    delivery = WebhookDelivery(
        subscription_id=dup.id,
        event_type="booth.transcription.started",
        payload={"test": "reassigned"},
    )
    db.add(delivery)
    await db.flush()
    delivery_id = delivery.id

    assert len((await db.execute(select(WebhookSubscription))).scalars().all()) == 2

    # Call create_webhook again — it should prune the duplicate and reassign pending deliveries!
    res3 = await create_webhook(req2, token=token, db=db)
    assert res3.id == orig_id
    subs_after_prune = (await db.execute(select(WebhookSubscription))).scalars().all()
    assert len(subs_after_prune) == 1
    assert subs_after_prune[0].id == orig_id

    # Verify delivery was preserved and reassigned to orig_id
    reassigned_del = (
        (await db.execute(select(WebhookDelivery).where(WebhookDelivery.id == delivery_id))).scalars().first()
    )
    assert reassigned_del is not None
    assert reassigned_del.subscription_id == orig_id


@pytest.mark.anyio
async def test_create_webhook_quota_limit(db, monkeypatch):
    from portal.config import settings
    from portal.models import DeveloperAccount, Event, OAuthClient, OAuthToken, User
    from portal.routers.webhooks import WebhookCreate, create_webhook

    monkeypatch.setattr("portal.routers.webhooks.validate_ssrf", lambda url: None)
    monkeypatch.setattr(settings, "max_webhook_subscriptions", 3)

    user = User(email="quota@example.com", display_name="Quota User", is_active=True)
    db.add(user)
    await db.flush()

    event = Event(slug="quota-event", display_name="Quota Event")
    db.add(event)
    await db.flush()

    dev_account = DeveloperAccount(user_id=user.id, status="approved")
    db.add(dev_account)
    await db.flush()

    client = OAuthClient(
        developer_account_id=dev_account.id,
        client_id="client_quota_123",
        name="Quota App",
    )
    db.add(client)
    await db.flush()

    token = OAuthToken(
        client_id=client.id,
        user_id=user.id,
        event_id=event.id,
        scopes=["webhooks:manage"],
        access_token_hash="hash123",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(token)
    await db.flush()

    for i in range(3):
        await create_webhook(
            WebhookCreate(target_url=f"https://example.com/wh/{i}", event_types=["test"]),
            token=token,
            db=db,
        )

    # Calling with a 4th distinct target URL should raise 429
    with pytest.raises(HTTPException) as exc_info:
        await create_webhook(
            WebhookCreate(target_url="https://example.com/wh/4", event_types=["test"]),
            token=token,
            db=db,
        )
    assert exc_info.value.status_code == 429

    # But re-subscribing to an EXISTING URL should still succeed (idempotent)!
    res_existing = await create_webhook(
        WebhookCreate(target_url="https://example.com/wh/1", event_types=["test", "extra"]),
        token=token,
        db=db,
    )
    assert res_existing.target_url == "https://example.com/wh/1"

    # Deactivating an existing subscription and creating a new one works within quota
    sub_row = (
        (
            await db.execute(
                select(WebhookSubscription).where(WebhookSubscription.target_url == "https://example.com/wh/1")
            )
        )
        .scalars()
        .first()
    )
    sub_row.is_active = False
    await db.flush()

    # Now create another sub to reach the quota of 3 active subs again
    await create_webhook(
        WebhookCreate(target_url="https://example.com/wh/filler", event_types=["test"]),
        token=token,
        db=db,
    )

    # Trying to reactivate the inactive sub while active quota is full raises 429
    with pytest.raises(HTTPException) as exc_info:
        await create_webhook(
            WebhookCreate(target_url="https://example.com/wh/1", event_types=["test"]),
            token=token,
            db=db,
        )
    assert exc_info.value.status_code == 429

    # But if one of the active subscriptions is a duplicate of the same URL,
    # reactivating the canonical sub will prune the duplicate, keeping total active count within quota.
    # Add an active duplicate of https://example.com/wh/1:
    dup_sub = WebhookSubscription(
        developer_account_id=client.developer_account_id,
        target_url="https://example.com/wh/1",
        event_types=["test"],
        secret_key="whsec_duplicate",
        is_active=True,
    )
    db.add(dup_sub)
    await db.flush()

    # Now active subs = 4 (wh/2, wh/3, wh/filler, wh/1-dup).
    # Deactivate wh/filler so active subs = 3 (quota limit of 3 is reached).
    filler_sub = (
        (
            await db.execute(
                select(WebhookSubscription).where(WebhookSubscription.target_url == "https://example.com/wh/filler")
            )
        )
        .scalars()
        .first()
    )
    filler_sub.is_active = False
    await db.flush()

    # Total active subs is 3 (wh/2, wh/3, and wh/1-dup).
    # Calling create_webhook for wh/1 should SUCCEED because pruning wh/1-dup keeps projected count at 3.
    res_reactivated = await create_webhook(
        WebhookCreate(target_url="https://example.com/wh/1", event_types=["test"]),
        token=token,
        db=db,
    )
    assert res_reactivated.target_url == "https://example.com/wh/1"
    assert res_reactivated.is_active is True
