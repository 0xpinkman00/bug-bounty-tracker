from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from backend.database import Base
from backend.main import overview, releases
from backend.models import Event, Program, Release, Repository

def test_overview_totals_and_recent_release_names() -> None:
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        program=Program(name='Example',platform='manual',platform_program_id='example',program_url='https://example.com')
        repository=Repository(owner='org',name='contracts',url='https://github.com/org/contracts',scan_failures=1)
        db.add_all([program,repository]);db.flush()
        db.add(Release(repository_id=repository.id,github_release_id=1,tag='v1',release_url='https://github.com/org/contracts/releases/tag/v1',published_at=datetime.now(timezone.utc)))
        db.add(Event(event_type='NEW_RELEASE',repository_id=repository.id,identity='1',payload={'tag':'v1'}))
        db.commit()
        result=overview(db)
        assert result['stats']=={'programs':1,'repositories':1,'releases':1,'releases_7d':1,'unread_events':1,'scan_failures':1}
        assert result['recent_releases'][0]['repository_name']=='org/contracts'
        assert result['recent_events'][0]['repository_name']=='org/contracts'
        assert releases(db, 0, 25)['items'][0]['repository_name']=='org/contracts'
