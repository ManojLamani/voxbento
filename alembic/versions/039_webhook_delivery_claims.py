"""Add recoverable webhook delivery claims.

Revision ID: 039
Revises: 038
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "039"
down_revision = "038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("webhook_deliveries") as batch:
        batch.add_column(sa.Column("claim_token", sa.String(32), nullable=True))
        batch.add_column(sa.Column("claim_until", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("webhook_deliveries") as batch:
        batch.drop_column("claim_until")
        batch.drop_column("claim_token")
