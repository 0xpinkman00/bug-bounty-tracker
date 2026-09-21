import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from backend.database import Base
from backend.github.scanner import register_repository, scan_repository
from backend.github.releases import poll_releases, poll_all_releases
import backend.github.releases as release_job
from backend.main import latest_release_run
from backend.models import Repository, Commit, Release, Tag, Event, Setting

class FakeGitHub:
    async def get(self, path, params=None):
        if path == '/repos/org/repo':
            return {'id': 10, 'owner': {'login':'org'}, 'name':'repo', 'full_name':'org/repo', 'html_url':'https://github.com/org/repo', 'default_branch':'main', 'archived':False}
        if path.endswith('/commits/main'):
            return {'sha':'abc'}
        if path.endswith('/commits'):
            return [{'sha':'abc','commit':{'message':'Add Vault','author':{'name':'Ada','date':'2026-01-01T00:00:00Z'}}}]
        if path.endswith('/commits/abc'):
            return {'files':[{'filename':'contracts/Vault.sol','status':'added','additions':4,'deletions':0,'patch':'@@ test'}]}
        if path.endswith('/releases'):
            return [{'id':20,'tag_name':'v1','name':'Version 1','published_at':'2026-01-01T00:00:00Z','html_url':'https://github.com/org/repo/releases/tag/v1'}]
        if path.endswith('/tags'):
            return [{'name':'v1','commit':{'sha':'abc'}}]
        raise AssertionError(path)

@pytest.mark.asyncio
async def test_registration_and_scan_are_idempotent() -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread':False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        client = FakeGitHub()
        repo = await register_repository(db, client, 'https://github.com/org/repo')
        same = await register_repository(db, client, 'https://github.com/org/repo/tree/main')
        assert repo.id == same.id
        await scan_repository(db, client, repo)
        await scan_repository(db, client, repo)
        assert len(db.scalars(select(Release)).all()) == 0
        first_poll = await poll_releases(db, client, repo)
        assert first_poll.fetched == 1
        assert first_poll.new_releases[0]['tag'] == 'v1'
        assert (await poll_releases(db, client, repo)).new_releases == ()
        assert len(db.scalars(select(Repository)).all()) == 1
        assert len(db.scalars(select(Commit)).all()) == 1
        assert len(db.scalars(select(Release)).all()) == 1
        assert len(db.scalars(select(Tag)).all()) == 1
        assert len(db.scalars(select(Event)).all()) == 4


@pytest.mark.asyncio
async def test_daily_poll_logs_repositories_and_new_releases(monkeypatch, caplog) -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Repository(owner='org', name='repo', url='https://github.com/org/repo'))
        db.commit()

    class Client(FakeGitHub):
        async def close(self):
            pass

    monkeypatch.setattr(release_job, 'SessionLocal', sessionmaker(engine))
    monkeypatch.setattr(release_job, 'GitHubClient', Client)
    with caplog.at_level('INFO', logger='backend.github.releases'):
        assert await poll_all_releases() == 0
        assert await poll_all_releases() == 0
    assert 'checked org/repo: 1 releases returned, 1 new' in caplog.text
    assert 'found release in org/repo:' in caplog.text
    assert '"tag": "v1"' in caplog.text
    assert 'checked org/repo: 1 releases returned, 0 new' in caplog.text
    assert '1 repositories checked, 1 new releases, 0 errors' in caplog.text
    with Session(engine) as db:
        latest = db.get(Setting, 'latest_release_poll').value
        assert latest['status'] == 'completed'
        assert latest['checked_count'] == 1
        assert latest['new_release_count'] == 0
        assert latest['repositories'][0]['repository'] == 'org/repo'
        assert latest['repositories'][0]['new_releases'] == []
        assert latest_release_run(db) == latest
