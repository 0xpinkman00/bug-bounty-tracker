"""Initial milestone schema."""
from alembic import op
from backend.database import Base
import backend.models  # noqa: F401

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

INITIAL_TABLES = (
    'programs', 'repositories', 'program_repositories', 'commits',
    'releases', 'tags', 'events', 'assets', 'program_snapshots',
    'changed_files', 'settings',
)

def upgrade() -> None:
    Base.metadata.create_all(op.get_bind(), tables=[Base.metadata.tables[name] for name in INITIAL_TABLES])

def downgrade() -> None:
    Base.metadata.drop_all(op.get_bind(), tables=[Base.metadata.tables[name] for name in INITIAL_TABLES])
