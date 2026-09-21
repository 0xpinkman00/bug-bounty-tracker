"""Persist source scrape position for pause and resume."""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.execute(sa.text("UPDATE source_sync_runs SET status = 'stopped', completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP) WHERE status IN ('queued', 'running')"))
    op.add_column('source_sync_runs', sa.Column('program_ids', sa.JSON(), nullable=False, server_default='[]'))
    op.add_column('source_sync_runs', sa.Column('next_index', sa.Integer(), nullable=False, server_default='0'))

def downgrade() -> None:
    op.drop_column('source_sync_runs', 'next_index')
    op.drop_column('source_sync_runs', 'program_ids')
