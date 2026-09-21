import asyncio
import logging
from celery import Celery
from sqlalchemy import select, or_
from backend.config import settings
from backend.database import SessionLocal
from backend.github.client import GitHubClient
from backend.github.scanner import scan_repository
from backend.models import Repository, Event, Setting, now
from backend.notifications.ubuntu import UbuntuNotificationProvider

log = logging.getLogger(__name__)
app = Celery('tracker', broker=settings.redis_url, backend=settings.redis_url)
app.conf.beat_schedule = {
    'scan-due-repositories': {'task': 'backend.workers.tasks.scan_due', 'schedule': 60.0},
    'send-notifications': {'task': 'backend.workers.tasks.send_notifications', 'schedule': 30.0},
}
DEFAULT_TYPES = ['NEW_PROGRAM', 'SCOPE_ADDED', 'SCOPE_REMOVED', 'NEW_REPOSITORY', 'NEW_RELEASE', 'NEW_TAG']

@app.task
def scan_one(repository_id: int) -> None:
    async def run() -> None:
        client = GitHubClient()
        try:
            with SessionLocal() as db:
                repo = db.get(Repository, repository_id)
                if repo:
                    await scan_repository(db, client, repo)
        finally:
            await client.close()
    asyncio.run(run())

@app.task
def scan_due() -> None:
    with SessionLocal() as db:
        ids = db.scalars(select(Repository.id).where(or_(Repository.next_scan_at <= now(), Repository.next_scan_at.is_(None)))).all()
    for repo_id in ids:
        scan_one.delay(repo_id)

@app.task
def send_notifications() -> None:
    async def run() -> None:
        provider = UbuntuNotificationProvider()
        with SessionLocal() as db:
            prefs = db.get(Setting, 'notifications')
            enabled = prefs.value.get('enabled', DEFAULT_TYPES) if prefs else DEFAULT_TYPES
            rows = db.scalars(select(Event).where(Event.event_type.in_(enabled)).order_by(Event.id).limit(100)).all()
            for item in rows:
                marker = db.get(Setting, f'notified:{item.id}')
                if marker:
                    continue
                if settings.notify_enabled:
                    await provider.send(item)
                db.add(Setting(key=f'notified:{item.id}', value={'sent': True}))
                db.commit()
    asyncio.run(run())

@app.task
def sync_source_run(run_id: int) -> None:
    from backend.services.discovery import synchronize_source_run
    asyncio.run(synchronize_source_run(run_id))

