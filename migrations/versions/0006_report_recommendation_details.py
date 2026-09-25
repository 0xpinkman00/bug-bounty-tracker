"""Add a recommendation section and extra detail rows to vulnerability reports."""
from alembic import op
import sqlalchemy as sa

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column('vulnerability_reports', sa.Column('recommendation', sa.Text(), nullable=False, server_default=''))
    op.add_column('vulnerability_reports', sa.Column('details', sa.JSON(), nullable=False, server_default='[]'))

def downgrade() -> None:
    op.drop_column('vulnerability_reports', 'details')
    op.drop_column('vulnerability_reports', 'recommendation')
