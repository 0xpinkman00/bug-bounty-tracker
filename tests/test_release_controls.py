import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.github import releases as release_job
from backend.main import start_release_scan, stop_release_scan
from backend.models import Repository, Setting
import backend.main as main


@pytest.mark.asyncio
async def test_manual_release_check_can_be_queued_and_stopped(monkeypatch) -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Repository(owner='org', name='repo', url='https://github.com/org/repo'))
        db.commit()

    queued = []

    class Task:
        def delay(self, run_id):
            queued.append(run_id)

    class Client:
        async def get(self, path, params=None):
            raise AssertionError('Stopped check must not request GitHub releases')

        async def close(self):
            pass

    class Notifier:
        async def send_text(self, title, message):
            return True

    monkeypatch.setattr(main, 'scan_releases_now', Task())
    monkeypatch.setattr(release_job, 'SessionLocal', sessionmaker(engine))
    monkeypatch.setattr(release_job, 'GitHubClient', Client)
    monkeypatch.setattr(release_job, 'UbuntuNotificationProvider', Notifier)

    with Session(engine) as db:
        started = start_release_scan(db)
        assert started['status'] == 'queued'
        assert started['total_repositories'] == 1
        assert queued == [started['id']]
        with pytest.raises(HTTPException) as duplicate:
            start_release_scan(db)
        assert duplicate.value.status_code == 409
        stopped = stop_release_scan(db)
        assert stopped['status'] == 'stopping'
        assert stopped['stop_requested'] is True

    assert await release_job.poll_all_releases(started['id']) == 0
    with Session(engine) as db:
        latest = db.get(Setting, 'latest_release_poll').value
        assert latest['status'] == 'stopped'
        assert latest['checked_count'] == 0
        assert latest['completed_at'] is not None
