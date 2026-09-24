from datetime import datetime, timedelta, timezone
import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from backend.database import Base
from backend.github import releases as release_job
from backend.github.client import RateLimitError, rate_limit_reset
from backend.github.ratelimit import rate_limit_status
from backend.main import github_rate_limit, start_release_scan
from backend.models import Repository, Setting, SourceSyncRun
from backend.services import discovery
from backend.sources.base import SourceProgram

RESET = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=30)

def engine():
    result = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(result)
    return result

def test_detects_primary_and_secondary_limits() -> None:
    request = httpx.Request('GET', 'https://api.github.com/x')
    primary = httpx.Response(403, headers={'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': str(int(RESET.timestamp()))}, request=request)
    secondary = httpx.Response(403, headers={'Retry-After': '60'}, json={'message': 'You have exceeded a secondary rate limit'}, request=request)
    forbidden = httpx.Response(403, json={'message': 'Resource not accessible'}, request=request)
    assert rate_limit_reset(primary) == RESET
    assert rate_limit_reset(secondary) > datetime.now(timezone.utc)
    assert rate_limit_reset(forbidden) is None

async def test_release_scan_stops_and_blocks_restart(monkeypatch) -> None:
    db_engine = engine()
    with Session(db_engine) as db:
        db.add_all([Repository(owner='org', name=name, url=f'https://github.com/org/{name}') for name in ('a', 'b', 'c')])
        db.commit()
    calls = []
    class Client:
        async def get(self, path, params=None):
            calls.append(path)
            if len(calls) == 2:
                raise RateLimitError(RESET)
            return []
        async def close(self): pass
    class Notifier:
        async def send_text(self, title, message): return True
    monkeypatch.setattr(release_job, 'SessionLocal', sessionmaker(db_engine))
    monkeypatch.setattr(release_job, 'GitHubClient', Client)
    monkeypatch.setattr(release_job, 'UbuntuNotificationProvider', Notifier)
    await release_job.poll_all_releases('run1')
    assert len(calls) == 2
    with Session(db_engine) as db:
        run = db.get(Setting, 'latest_release_poll').value
        assert (run['status'], run['checked_count'], run['error_count']) == ('rate_limited', 1, 0)
        assert run['rate_limit_reset_at'] == RESET.isoformat()
        assert github_rate_limit(db)['reset_at'] == RESET.isoformat()
        with pytest.raises(HTTPException) as refused:
            start_release_scan(db)
        assert refused.value.status_code == 429

async def test_source_scan_pauses_on_the_limited_program(monkeypatch) -> None:
    db_engine = engine()
    factory = sessionmaker(db_engine, expire_on_commit=False)
    class Source:
        async def list_programs(self): return ['one', 'two', 'three']
        async def get_program(self, identifier):
            return SourceProgram('immunefi', identifier, identifier, 'https://example.com', repositories=['https://github.com/org/repo'] if identifier == 'two' else [])
        async def close(self): pass
    class Client:
        async def close(self): pass
    async def register(db, client, url):
        raise RateLimitError(RESET)
    monkeypatch.setattr(discovery, 'SessionLocal', factory)
    monkeypatch.setattr(discovery, 'GitHubClient', Client)
    monkeypatch.setattr(discovery, 'register_repository', register)
    monkeypatch.setattr(discovery, 'SOURCE_CLASSES', {'immunefi': Source})
    with factory() as db:
        run, _ = discovery.create_source_run(db, 'immunefi')
    await discovery.synchronize_source_run(run.id)
    with factory() as db:
        stored = db.get(SourceSyncRun, run.id)
        assert (stored.status, stored.next_index, stored.processed_count) == ('paused', 1, 1)
        assert 'GitHub rate limit reached' in stored.last_error
        assert rate_limit_status(db) is not None
