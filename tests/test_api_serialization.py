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
