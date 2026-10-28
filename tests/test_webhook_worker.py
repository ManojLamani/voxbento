from __future__ import annotations

import asyncio
import json
import os
import runpy
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import HTTPException
from sqlalchemy import event, inspect, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from portal import database
from portal.models import DeveloperAccount, OAuthAuditLog, OAuthClient, User, WebhookDelivery, WebhookSubscription
from portal.webhooks import worker
from portal.webhooks.worker import webhook_worker_loop


@dataclass(frozen=True)
class QueueState:
    user_id: int
    subscription_id: int


@pytest.fixture(params=["sqlite", "postgresql"])
async def queue_db(tmp_path, monkeypatch, request):
    postgres_url = os.getenv("WEBHOOK_TEST_POSTGRES_URL")
    if request.param == "postgresql" and not postgres_url:
        pytest.skip("Set WEBHOOK_TEST_POSTGRES_URL to exercise real PostgreSQL transactions")
    monkeypatch.setattr(database, "_engine", None)
    monkeypatch.setattr(database, "_async_session_factory", None)
    schema = "webhook_test_" + secrets.token_hex(8)
    if request.param == "postgresql":
        # A unique schema per test keeps even an explicitly supplied database untouched.
        database.configure(postgres_url)
        async with database._engine.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        await database.dispose()
        database._engine = create_async_engine(postgres_url, connect_args={"server_settings": {"search_path": schema}})
        database._async_session_factory = async_sessionmaker(database._engine, expire_on_commit=False)
    else:
        database.configure(f"sqlite+aiosqlite:///{tmp_path / 'webhooks.db'}")
    monkeypatch.setattr(worker, "validate_ssrf", lambda url: None)
    await database.init_db()
    try:
        async with database.get_session() as session:
            user = User(email="webhook@example.invalid", display_name="Before")
            session.add(user)
            await session.flush()
            account = DeveloperAccount(user_id=user.id, status="approved")
            session.add(account)
            await session.flush()
            subscription = WebhookSubscription(
                developer_account_id=account.id,
                target_url="https://receiver.example.invalid/hook",
                secret_key="test-secret",
                event_types=["session.status_changed"],
            )
            session.add(subscription)
            await session.flush()
            state = QueueState(user.id, subscription.id)
        yield state
    finally:
        if request.param == "postgresql":
            async with database._engine.begin() as connection:
                await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await database.dispose()


async def enqueue(state: QueueState, count: int = 1) -> list[int]:
    async with database.get_session() as session:
        deliveries = [
            WebhookDelivery(
                subscription_id=state.subscription_id,
                event_type="session.status_changed",
                payload={"sequence": i},
            )
            for i in range(count)
        ]
        session.add_all(deliveries)
        await session.flush()
        return [delivery.id for delivery in deliveries]


@pytest.mark.anyio
@pytest.mark.parametrize("response_status", [200, 503])
async def test_worker_releases_write_lock_during_http(queue_db, monkeypatch, response_status):
    await enqueue(queue_db, count=2)
    entered = asyncio.Event()
    release = asyncio.Event()
    responses = 0

    async def receive(request):
        nonlocal responses
        entered.set()
        await release.wait()
        responses += 1
        return httpx.Response(response_status, request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(receive))
    monkeypatch.setattr(worker.httpx, "AsyncClient", lambda **kwargs: client)
    task = asyncio.create_task(webhook_worker_loop())
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        # A separate connection must commit before the receiver is allowed to respond.
        async with asyncio.timeout(1):
            async with database.get_session() as session:
                await session.execute(update(User).where(User.id == queue_db.user_id).values(display_name="After"))
        assert responses == 0
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def get_delivery(delivery_id: int) -> WebhookDelivery:
    async with database.get_session() as session:
        return await session.get(WebhookDelivery, delivery_id)


async def expire_claim(claim: worker.DeliveryClaim) -> None:
    async with database.get_session() as session:
        await session.execute(
            update(WebhookDelivery)
            .where(WebhookDelivery.id == claim.delivery_id)
            .values(claim_until=datetime.now(timezone.utc) - timedelta(seconds=1))
        )


@pytest.mark.anyio
async def test_success_commits_result_signature_and_resets_failures(queue_db):
    [delivery_id] = await enqueue(queue_db)
    async with database.get_session() as session:
        await session.execute(
            update(WebhookSubscription)
            .where(WebhookSubscription.id == queue_db.subscription_id)
            .values(consecutive_failures=3)
        )
    requests = []

    def receive(request):
        requests.append(request)
        return httpx.Response(200, request=request)

    claim = await worker.claim_delivery()
    async with httpx.AsyncClient(transport=httpx.MockTransport(receive)) as client:
        await worker.process_delivery(client, claim)
    delivery = await get_delivery(delivery_id)
    assert (delivery.status, delivery.attempt_count, delivery.last_error) == ("succeeded", 1, None)
    assert delivery.claim_token is None and delivery.claim_until is None
    async with database.get_session() as session:
        assert (await session.get(WebhookSubscription, queue_db.subscription_id)).consecutive_failures == 0
    [request] = requests
    envelope = json.loads(request.content)
    assert envelope == {
        "delivery_id": delivery_id,
        "event_type": "session.status_changed",
        "payload_version": "1",
        "data": {"sequence": 0},
    }
    timestamp, signature = request.headers["X-VoxBento-Signature"].split(",v1=")
    assert signature == worker.sign_payload("test-secret", request.content.decode(), int(timestamp[2:]))


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["status", "request", "deadline"])
async def test_retry_backoff_and_four_attempt_limit(queue_db, monkeypatch, failure):
    [delivery_id] = await enqueue(queue_db)
    monkeypatch.setattr(worker, "DELIVERY_TIMEOUT_SECONDS", 0.05 if failure == "deadline" else 15)

    async def receive(request):
        if failure == "request":
            raise httpx.ReadTimeout("test timeout", request=request)
        if failure == "deadline":
            await asyncio.Event().wait()
        return httpx.Response(503, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(receive)) as client:
        for attempt in range(1, 5):
            claim = await worker.claim_delivery()
            started = datetime.now(timezone.utc)
            await worker.process_delivery(client, claim)
            delivery = await get_delivery(delivery_id)
            assert delivery.attempt_count == attempt
            assert delivery.status == ("dead" if attempt == 4 else "failed")
            assert delivery.last_error
            assert delivery.claim_token is None and delivery.claim_until is None
            if attempt < 4:
                assert delivery.next_attempt_at.replace(tzinfo=timezone.utc) >= started + timedelta(seconds=2**attempt)
                assert await worker.claim_delivery() is None
                async with database.get_session() as session:
                    await session.execute(
                        update(WebhookDelivery).where(WebhookDelivery.id == delivery_id).values(next_attempt_at=started)
                    )
        assert await worker.claim_delivery() is None


@pytest.mark.anyio
@pytest.mark.parametrize("with_clients", [False, True])
async def test_circuit_breaker_and_audit_are_recorded_once(queue_db, with_clients):
    [delivery_id] = await enqueue(queue_db)
    async with database.get_session() as session:
        sub = await session.get(WebhookSubscription, queue_db.subscription_id)
        sub.consecutive_failures = 4
        if with_clients:
            clients = [
                OAuthClient(developer_account_id=sub.developer_account_id, client_id=f"client-{i}", name=f"C{i}")
                for i in range(2)
            ]
            session.add_all(clients)
            await session.flush()
            expected_client_id = clients[0].id
        else:
            expected_client_id = None
        await session.execute(update(WebhookDelivery).where(WebhookDelivery.id == delivery_id).values(attempt_count=3))
    claim = await worker.claim_delivery()
    await worker.finish_delivery(claim, "HTTP error: 503")
    await worker.finish_delivery(claim, "HTTP error: 503")
    async with database.get_session() as session:
        sub = await session.get(WebhookSubscription, queue_db.subscription_id)
        assert not sub.is_active and sub.consecutive_failures == 5
        [audit] = (await session.scalars(select(OAuthAuditLog))).all()
        assert audit.action == "webhook.circuit_breaker_tripped" and audit.client_id == expected_client_id


@pytest.mark.anyio
async def test_concurrent_terminal_failures_serialize_subscription_accounting(queue_db):
    await enqueue(queue_db, 5)
    async with database.get_session() as session:
        await session.execute(update(WebhookDelivery).values(attempt_count=3))
    claims = [await worker.claim_delivery() for _ in range(5)]
    await asyncio.gather(*(worker.finish_delivery(claim, "HTTP error: 503") for claim in claims))
    async with database.get_session() as session:
        sub = await session.get(WebhookSubscription, queue_db.subscription_id)
        assert not sub.is_active and sub.consecutive_failures == 5
        assert len((await session.scalars(select(OAuthAuditLog))).all()) == 1


@pytest.mark.anyio
async def test_two_workers_claim_distinct_deliveries(queue_db):
    ids = await enqueue(queue_db, 2)
    claims = await asyncio.gather(worker.claim_delivery(), worker.claim_delivery(), worker.claim_delivery())
    assert sorted(claim.delivery_id for claim in claims if claim is not None) == ids
    assert await worker.claim_delivery() is None


@pytest.mark.anyio
async def test_expired_claim_recovers_and_fences_old_results(queue_db):
    [delivery_id] = await enqueue(queue_db)
    old = await worker.claim_delivery()
    assert await worker.claim_delivery() is None
    await expire_claim(old)
    recovered = await worker.claim_delivery()
    assert recovered.delivery_id == delivery_id and recovered.token != old.token
    await worker.finish_delivery(old, "HTTP error: 503")
    await worker.release_claim(old)
    delivery = await get_delivery(delivery_id)
    assert delivery.status == "delivering" and delivery.claim_token == recovered.token
    assert delivery.attempt_count == 0
    await worker.finish_delivery(recovered, None)
    await worker.finish_delivery(old, "HTTP error: 503")
    delivery = await get_delivery(delivery_id)
    assert delivery.status == "succeeded" and delivery.attempt_count == 1


@pytest.mark.anyio
async def test_legacy_claim_without_lease_recovers(queue_db):
    [delivery_id] = await enqueue(queue_db)
    async with database.get_session() as session:
        await session.execute(
            update(WebhookDelivery).where(WebhookDelivery.id == delivery_id).values(status="delivering")
        )
    claim = await worker.claim_delivery()
    assert claim.delivery_id == delivery_id
    assert (await get_delivery(delivery_id)).claim_until is not None


@pytest.mark.anyio
async def test_cancellation_releases_claim_and_retries_same_delivery_id(queue_db):
    [delivery_id] = await enqueue(queue_db)
    entered = asyncio.Event()

    async def receive(request):
        entered.set()
        await asyncio.Event().wait()

    old = await worker.claim_delivery()
    async with httpx.AsyncClient(transport=httpx.MockTransport(receive)) as client:
        task = asyncio.create_task(worker.process_delivery(client, old))
        await asyncio.wait_for(entered.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    delivery = await get_delivery(delivery_id)
    assert delivery.status == "failed" and delivery.claim_token is None
    recovered = await worker.claim_delivery()
    assert recovered.delivery_id == delivery_id and recovered.token != old.token


@pytest.mark.anyio
async def test_result_commit_failure_can_retry_same_delivery(queue_db):
    [delivery_id] = await enqueue(queue_db)
    async with database.get_session() as session:
        await session.execute(
            update(WebhookSubscription)
            .where(WebhookSubscription.id == queue_db.subscription_id)
            .values(consecutive_failures=3)
        )
    claim = await worker.claim_delivery()
    fail_next_commit = False

    def fail_commit(connection):
        nonlocal fail_next_commit
        if fail_next_commit:
            fail_next_commit = False
            raise SQLAlchemyError("result commit failed")

    def receive(request):
        nonlocal fail_next_commit
        fail_next_commit = True
        return httpx.Response(200, request=request)

    event.listen(database._engine.sync_engine, "commit", fail_commit)
    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(receive)) as client:
            with pytest.raises(SQLAlchemyError, match="result commit failed"):
                await worker.process_delivery(client, claim)
    finally:
        event.remove(database._engine.sync_engine, "commit", fail_commit)
    delivery = await get_delivery(delivery_id)
    assert delivery.status == "failed" and delivery.attempt_count == 0
    async with database.get_session() as session:
        assert (await session.get(WebhookSubscription, queue_db.subscription_id)).consecutive_failures == 3
    assert (await worker.claim_delivery()).delivery_id == delivery_id


@pytest.mark.anyio
@pytest.mark.parametrize("reason", ["inactive", "deleted", "invalid_url"])
async def test_no_dispatch_for_unavailable_subscription_or_invalid_url(queue_db, monkeypatch, reason):
    [delivery_id] = await enqueue(queue_db)
    claim = await worker.claim_delivery()
    if reason == "invalid_url":

        def reject(url):
            raise HTTPException(status_code=400, detail="forbidden address")

        monkeypatch.setattr(worker, "validate_ssrf", reject)
    else:
        async with database.get_session() as session:
            sub = await session.get(WebhookSubscription, queue_db.subscription_id)
            if reason == "inactive":
                sub.is_active = False
            else:
                await session.delete(sub)

    def unexpected_request(request):
        pytest.fail("An unavailable subscription must not receive a request")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected_request)) as client:
        await worker.process_delivery(client, claim)
    delivery = await get_delivery(delivery_id)
    if reason == "deleted":
        assert delivery is None
    else:
        assert delivery.status == "dead" and delivery.attempt_count == 0


@pytest.mark.anyio
async def test_claim_migration_preserves_existing_deliveries(queue_db):
    [delivery_id] = await enqueue(queue_db)
    migration = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "alembic/versions/039_webhook_delivery_claims.py")
    )

    def migrate(connection):
        with Operations.context(MigrationContext.configure(connection)):
            migration["downgrade"]()
            columns = {column["name"] for column in inspect(connection).get_columns("webhook_deliveries")}
            assert "claim_token" not in columns and "claim_until" not in columns
            migration["upgrade"]()
        columns = {column["name"] for column in inspect(connection).get_columns("webhook_deliveries")}
        assert {"claim_token", "claim_until"} <= columns

    async with database._engine.begin() as connection:
        await connection.run_sync(migrate)
    claim = await worker.claim_delivery()
    assert claim.delivery_id == delivery_id
    await worker.finish_delivery(claim, None)
    assert (await get_delivery(delivery_id)).status == "succeeded"
