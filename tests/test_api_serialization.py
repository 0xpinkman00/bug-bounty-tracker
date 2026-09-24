import json
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from backend.database import Base
from backend.main import programs, repositories
from backend.models import Program, Repository

def test_program_and_repository_lists_serialize_metadata() -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Program(name='Example', platform='manual', platform_program_id='example', program_url='https://example.com', metadata_json={'category': 'defi'}))
        db.add(Repository(owner='org', name='repo', url='https://github.com/org/repo', metadata_json={'watch': True}))
        db.commit()
        program_page = programs(db, 0, 25, '', '', 'all')
        repository_page = repositories(db, 0, 25, '')
        assert program_page['items'][0]['metadata'] == {'category': 'defi'}
        assert repository_page['items'][0]['metadata'] == {'watch': True}
        json.dumps(program_page)
        json.dumps(repository_page)

def test_repositories_are_ordered_by_latest_release() -> None:
    from datetime import datetime, timezone
    from backend.models import Release
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        old, new, none = (Repository(owner='org', name=name, url=f'https://github.com/org/{name}') for name in ('old', 'new', 'none'))
        db.add_all([old, new, none]); db.flush()
        at = lambda day: datetime(2026, 9, day, tzinfo=timezone.utc)
        db.add_all([Release(repository_id=old.id, github_release_id=1, tag='v1', published_at=at(1), release_url='u'),
                    Release(repository_id=old.id, github_release_id=2, tag='v2', published_at=at(10), release_url='u'),
                    Release(repository_id=new.id, github_release_id=3, tag='v9', published_at=at(20), release_url='u')])
        db.commit()
        items = repositories(db, 0, 25, '')['items']
        assert [(item['name'], item['latest_release'] and item['latest_release']['tag']) for item in items] == [('new', 'v9'), ('old', 'v2'), ('none', None)]
        json.dumps(items)
