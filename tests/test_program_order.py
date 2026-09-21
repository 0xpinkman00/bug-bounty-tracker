from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.main import programs
from backend.models import Program, Repository, Release


def test_programs_sort_by_latest_release_or_update_before_pagination() -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def day(number: int) -> datetime:
        return datetime(2026, 1, number, tzinfo=timezone.utc)

    with Session(engine) as db:
        older = Program(name='Older release', platform='manual', platform_program_id='older',
                        program_url='https://example.com/older', first_seen_at=day(1), last_changed_at=day(1))
        updated = Program(name='Updated program', platform='manual', platform_program_id='updated',
                          program_url='https://example.com/updated', first_seen_at=day(1), last_changed_at=day(10))
        newest = Program(name='Newest release', platform='manual', platform_program_id='newest',
                         program_url='https://example.com/newest', first_seen_at=day(1), last_changed_at=day(3))
        old_repo = Repository(owner='example', name='old', url='https://github.com/example/old')
        new_repo = Repository(owner='example', name='new', url='https://github.com/example/new')
        older.repositories.append(old_repo)
        newest.repositories.append(new_repo)
        db.add_all([older, updated, newest])
        db.flush()
        db.add_all([
            Release(repository_id=old_repo.id, github_release_id=1, tag='v1', release_url='https://example.com/v1', published_at=day(5)),
            Release(repository_id=new_repo.id, github_release_id=2, tag='v2', release_url='https://example.com/v2', published_at=day(12)),
        ])
        db.commit()

        first = programs(db, 0, 2, '', '')
        second = programs(db, 2, 2, '', '')
        assert first['total'] == second['total'] == 3
        assert [item['name'] for item in first['items'] + second['items']] == [
            'Newest release', 'Updated program', 'Older release'
        ]
        assert [item['latest_activity_at'][:10] for item in first['items'] + second['items']] == [
            '2026-01-12', '2026-01-10', '2026-01-05'
        ]
        all_programs = programs(db, 0, 2, '', '', 'all')
        assert all_programs['total'] == 3
        assert [item['name'] for item in all_programs['items']] == ['Newest release', 'Updated program']
        linked = programs(db, 0, 25, '', '', 'linked')
        assert linked['total'] == 2
        assert [item['name'] for item in linked['items']] == ['Newest release', 'Older release']
        unlinked = programs(db, 0, 25, '', '', 'unlinked')
        assert unlinked['total'] == 1
        assert [item['name'] for item in unlinked['items']] == ['Updated program']
