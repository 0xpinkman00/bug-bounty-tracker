"""Record what changed in each program update."""
from alembic import op
import sqlalchemy as sa

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table('program_updates',
                    sa.Column('id', sa.Integer(), primary_key=True),
                    sa.Column('program_id', sa.Integer(), sa.ForeignKey('programs.id', ondelete='CASCADE'), nullable=False),
                    sa.Column('categories', sa.JSON(), nullable=False),
                    sa.Column('changes', sa.JSON(), nullable=False),
                    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index('ix_program_updates_program_id', 'program_updates', ['program_id'])

def downgrade() -> None:
    op.drop_index('ix_program_updates_program_id', 'program_updates')
    op.drop_table('program_updates')
