"""Track source sync progress and results."""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'source_sync_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('discovered_count', sa.Integer(), nullable=False),
        sa.Column('processed_count', sa.Integer(), nullable=False),
        sa.Column('created_count', sa.Integer(), nullable=False),
        sa.Column('updated_count', sa.Integer(), nullable=False),
        sa.Column('error_count', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_source_sync_runs_source', 'source_sync_runs', ['source'])

def downgrade() -> None:
    op.drop_index('ix_source_sync_runs_source', table_name='source_sync_runs')
    op.drop_table('source_sync_runs')
