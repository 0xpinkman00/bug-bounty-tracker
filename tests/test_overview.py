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


def test_releases_list_shows_only_the_latest_release_per_repository() -> None:
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first=Repository(owner='org',name='contracts',url='https://github.com/org/contracts')
        second=Repository(owner='org',name='sdk',url='https://github.com/org/sdk')
        db.add_all([first,second]);db.flush()
        # Older rows left behind by polls that ran before only the newest release was kept.
        db.add_all([
            Release(repository_id=first.id,github_release_id=1,tag='v1',release_url='https://example.com/v1',published_at=datetime(2026,1,1,tzinfo=timezone.utc)),
            Release(repository_id=first.id,github_release_id=2,tag='v2',release_url='https://example.com/v2',published_at=datetime(2026,2,1,tzinfo=timezone.utc)),
            Release(repository_id=first.id,github_release_id=3,tag='v3',release_url='https://example.com/v3',published_at=datetime(2026,3,1,tzinfo=timezone.utc)),
            Release(repository_id=second.id,github_release_id=4,tag='sdk-v1',release_url='https://example.com/sdk-v1',published_at=datetime(2026,2,15,tzinfo=timezone.utc)),
        ])
        db.commit()
        result=releases(db, 0, 25)
        assert result['total']==2
        assert [item['tag'] for item in result['items']]==['v3','sdk-v1']
        assert all(item['published_at'] for item in result['items'])


def test_program_detail_does_not_include_releases() -> None:
    from backend.main import program_detail
    from backend.models import Program, ProgramRepository
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        program=Program(name='Acme',platform='manual',platform_program_id='acme',program_url='https://example.com/acme')
        contracts=Repository(owner='org',name='contracts',url='https://github.com/org/contracts')
        db.add_all([program,contracts]);db.flush()
        db.add(ProgramRepository(program_id=program.id,repository_id=contracts.id))
        db.add(Release(repository_id=contracts.id,github_release_id=1,tag='v1',release_url='https://example.com/v1',published_at=datetime(2026,1,1,tzinfo=timezone.utc)))
        db.commit()
        detail=program_detail(program.id, db)
        # Releases are tracked per repository only; the program page no longer rolls them up.
        assert 'releases' not in detail
        assert [repo['id'] for repo in detail['repositories']]==[contracts.id]
