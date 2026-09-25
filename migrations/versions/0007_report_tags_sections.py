"""Add tags and extra sections to vulnerability reports."""
from alembic import op
import sqlalchemy as sa

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column('vulnerability_reports', sa.Column('extra_sections', sa.JSON(), nullable=False, server_default='[]'))
    op.add_column('vulnerability_reports', sa.Column('tags', sa.JSON(), nullable=False, server_default='[]'))

def downgrade() -> None:
    op.drop_column('vulnerability_reports', 'tags')
    op.drop_column('vulnerability_reports', 'extra_sections')
