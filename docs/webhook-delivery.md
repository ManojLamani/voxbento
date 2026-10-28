# Webhook delivery and recovery

Webhook dispatch uses short transactions to claim one delivery and to save its
result. DNS validation and HTTP requests run after the read session is closed, so
slow receivers do not hold SQLite write locks or PostgreSQL row locks.

Migration `039` adds `claim_token` and `claim_until` to `webhook_deliveries`.
Run `uv run alembic upgrade head` before starting the updated portal. Stop older
portal workers during rollout; they do not understand committed claims.

A claim lasts 60 seconds. The complete validation and HTTP operation has a
15-second deadline, in addition to the HTTP client's five-second phase timeouts.
The worker releases a claim when cancelled or when saving a result fails. If the
process terminates before cleanup, a subsequent worker recovers the claim after
its lease expires. Legacy `delivering` rows with no lease are also recovered.
Claim tokens fence result updates and cleanup, so a late worker cannot change a
delivery or subscription counters after another worker has claimed it.

Delivery is **at least once**. A receiver may accept a request before the worker
can commit its result; recovery then sends it again with the same `delivery_id`.
Receivers should deduplicate that ID. The timestamp and HMAC signature are rebuilt
for each request. Exactly-once delivery across an HTTP request and a database
transaction is not guaranteed.

Recorded HTTP failures use the existing four-attempt limit and exponential
backoff (2, 4, then 8 seconds). Interrupted attempts without a recorded result do
not consume this limit. Five exhausted deliveries disable a subscription; a
successful delivery resets its consecutive-failure counter. Invalid destinations
and inactive subscriptions are marked dead without sending a request.

The regression suite uses file-backed SQLite and separate connections. To run
the same cases on PostgreSQL, install the `asyncpg` driver and set
`WEBHOOK_TEST_POSTGRES_URL` to an asyncpg URL for a test database. Each test creates
and removes its own schema; the database user needs schema creation permission.

```bash
uv run --with asyncpg pytest tests/test_webhook_worker.py tests/test_webhooks.py -q
```
