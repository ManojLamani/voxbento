from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import HTTPException
from sqlalchemy import or_, select, update
from sqlalchemy.exc import SQLAlchemyError

from portal.database import get_session
from portal.models import OAuthAuditLog, OAuthClient, WebhookDelivery, WebhookSubscription
from portal.routers.webhooks import validate_ssrf

logger = logging.getLogger(__name__)


async def enqueue_webhook(event_type: str, payload: dict) -> None:
    """Helper to insert a new webhook delivery into the queue."""
    try:
        async with get_session() as db:
            result = await db.execute(select(WebhookSubscription).where(WebhookSubscription.is_active.is_(True)))
            subs = result.scalars().all()

            deliveries = []
            for sub in subs:
                if event_type in sub.event_types:
                    delivery = WebhookDelivery(
                        subscription_id=sub.id,
                        event_type=event_type,
                        payload=payload,
                        payload_version="1",
                        status="pending",
                    )
                    deliveries.append(delivery)

            if deliveries:
                db.add_all(deliveries)
                await db.flush()
    except Exception as e:
        logger.error(f"Failed to enqueue webhook: {e}", exc_info=True)


def sign_payload(secret: str, payload_str: str, timestamp: int) -> str:
    """Generate the X-VoxBento-Signature HMAC-SHA256."""
    mac = hmac.new(secret.encode(), msg=f"{timestamp}.{payload_str}".encode(), digestmod=hashlib.sha256)
    return mac.hexdigest()


DELIVERY_TIMEOUT_SECONDS = 15.0
CLAIM_DURATION = timedelta(seconds=60)
MAX_ATTEMPTS = 4


@dataclass(frozen=True)
class DeliveryClaim:
    delivery_id: int
    token: str
    attempt_count: int


async def claim_delivery() -> DeliveryClaim | None:
    """Commit one exclusive claim before performing any network I/O."""
    now = datetime.now(timezone.utc)
    async with get_session() as db:
        # NULL leases include deliveries left by the worker before migration 039.
        await db.execute(
            update(WebhookDelivery)
            .where(
                WebhookDelivery.status == "delivering",
                or_(WebhookDelivery.claim_until <= now, WebhookDelivery.claim_until.is_(None)),
            )
            .values(status="failed", claim_token=None, claim_until=None, next_attempt_at=now)
        )
        ready = (
            WebhookDelivery.status.in_(["pending", "failed"]),
            WebhookDelivery.next_attempt_at <= now,
        )
        candidate = (
            select(WebhookDelivery.id)
            .where(*ready)
            .order_by(WebhookDelivery.next_attempt_at, WebhookDelivery.id)
            .limit(1)
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        token = secrets.token_hex(16)
        result = await db.execute(
            update(WebhookDelivery)
            .where(WebhookDelivery.id == candidate, *ready)
            .values(status="delivering", claim_token=token, claim_until=now + CLAIM_DURATION)
            .returning(WebhookDelivery.id, WebhookDelivery.attempt_count)
        )
        row = result.first()
        return DeliveryClaim(row.id, token, row.attempt_count) if row else None


async def release_claim(claim: DeliveryClaim) -> None:
    """Make interrupted work available without releasing a newer owner's claim."""
    async with get_session() as db:
        await db.execute(
            update(WebhookDelivery)
            .where(
                WebhookDelivery.id == claim.delivery_id,
                WebhookDelivery.status == "delivering",
                WebhookDelivery.claim_token == claim.token,
            )
            .values(status="failed", claim_token=None, claim_until=None, next_attempt_at=datetime.now(timezone.utc))
        )


async def finish_delivery(
    claim: DeliveryClaim, error: str | None, *, permanent: bool = False, attempted: bool = True
) -> None:
    """Record a result and subscription accounting atomically, fencing stale owners."""
    attempts = claim.attempt_count + int(attempted)
    status = "succeeded" if error is None else ("dead" if permanent or attempts >= MAX_ATTEMPTS else "failed")
    async with get_session() as db:
        result = await db.execute(
            update(WebhookDelivery)
            .where(
                WebhookDelivery.id == claim.delivery_id,
                WebhookDelivery.status == "delivering",
                WebhookDelivery.claim_token == claim.token,
            )
            .values(
                status=status,
                attempt_count=attempts,
                last_error=error[:2000] if error else None,
                next_attempt_at=datetime.now(timezone.utc) + timedelta(seconds=2**attempts),
                claim_token=None,
                claim_until=None,
            )
            .returning(WebhookDelivery.subscription_id)
        )
        subscription_id = result.scalar_one_or_none()
        if subscription_id is None or not attempted:
            return

        sub = await db.scalar(
            select(WebhookSubscription).where(WebhookSubscription.id == subscription_id).with_for_update()
        )
        if sub is None:
            return
        if status == "succeeded":
            sub.consecutive_failures = 0
        elif status == "dead" and sub.is_active:
            sub.consecutive_failures += 1
            if sub.consecutive_failures >= 5:
                sub.is_active = False
                client_id = await db.scalar(
                    select(OAuthClient.id)
                    .where(OAuthClient.developer_account_id == sub.developer_account_id)
                    .order_by(OAuthClient.id)
                    .limit(1)
                )
                db.add(
                    OAuthAuditLog(
                        client_id=client_id,
                        action="webhook.circuit_breaker_tripped",
                        request_path=f"/dispatch/{sub.id}",
                        status_code=500,
                    )
                )


async def process_delivery(client: httpx.AsyncClient, claim: DeliveryClaim) -> None:
    try:
        async with get_session() as db:
            delivery = await db.scalar(
                select(WebhookDelivery).where(
                    WebhookDelivery.id == claim.delivery_id,
                    WebhookDelivery.status == "delivering",
                    WebhookDelivery.claim_token == claim.token,
                )
            )
            if delivery is None:
                return
            sub = await db.get(WebhookSubscription, delivery.subscription_id)
            active = sub is not None and sub.is_active
            target_url = sub.target_url if sub else ""
            secret = sub.secret_key if sub else ""
            payload_str = json.dumps(
                {
                    "delivery_id": delivery.id,
                    "event_type": delivery.event_type,
                    "payload_version": delivery.payload_version,
                    "data": delivery.payload,
                }
            )

        if not active:
            await finish_delivery(claim, "Subscription is inactive or deleted.", permanent=True, attempted=False)
            return

        error = None
        permanent = False
        attempted = True
        try:
            # Bound the complete operation, not just each individual HTTP phase.
            # The lease is longer than this deadline; DNS must not block the event loop.
            async with asyncio.timeout(DELIVERY_TIMEOUT_SECONDS):
                await asyncio.to_thread(validate_ssrf, target_url)
                timestamp = int(time.time())
                signature = sign_payload(secret, payload_str, timestamp)
                headers = {"Content-Type": "application/json", "X-VoxBento-Signature": f"t={timestamp},v1={signature}"}
                response = await client.post(target_url, content=payload_str, headers=headers)
                response.raise_for_status()
        except HTTPException as exc:
            error = f"SSRF Validation failed at dispatch: {exc}"
            permanent = True
            attempted = False
        except httpx.RequestError as exc:
            error = f"Request error: {exc}"
        except httpx.HTTPStatusError as exc:
            error = f"HTTP error: {exc.response.status_code}"
        except TimeoutError:
            error = "Webhook delivery exceeded its total timeout."

        await finish_delivery(claim, error, permanent=permanent, attempted=attempted)
    except BaseException:
        # Cancellation and failed result commits must not strand committed claims.
        # If cleanup also fails, the lease still allows a later worker to recover.
        try:
            await release_claim(claim)
        except SQLAlchemyError:
            logger.exception("Could not release webhook delivery %s; its lease will expire", claim.delivery_id)
        raise


async def webhook_worker_loop() -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        while True:
            try:
                claim = await claim_delivery()
                if claim is None:
                    await asyncio.sleep(1)
                else:
                    await process_delivery(client, claim)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Webhook worker error")
                await asyncio.sleep(5)
