"""Daily GitHub release polling, independent of the regular repository scan."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.github.client import GitHubClient, RateLimitError
from backend.github.ratelimit import rate_limit_error, record_rate_limit
from backend.github.scanner import event, parse_date
from backend.models import Release, Repository, Setting
from backend.notifications.ubuntu import UbuntuNotificationProvider

log = logging.getLogger(__name__)
LATEST_RUN_KEY = 'latest_release_poll'
POLL_LOCK_ID = 2847194301


@dataclass(frozen=True)
class ReleasePollResult:
    fetched: int
    new_releases: tuple[dict, ...]


async def poll_releases(db: Session, client: GitHubClient, repo: Repository) -> ReleasePollResult:
    rows = await client.get(f'/repos/{repo.owner}/{repo.name}/releases', {'per_page': 100})
    if not isinstance(rows, list):
        raise ValueError(f'Unexpected releases response for {repo.owner}/{repo.name}')
    found = []
    # GitHub returns releases newest first; only the most recent one is tracked,
    # intermediate releases between two polls are ignored.
    if rows:
        item = rows[0]
        if not db.scalar(select(Release.id).where(Release.repository_id == repo.id,
                                                  Release.github_release_id == item['id'])):
            db.add(Release(repository_id=repo.id, github_release_id=item['id'], tag=item['tag_name'],
                           name=item.get('name'), commit_sha=None, published_at=parse_date(item.get('published_at')),
                           release_url=item['html_url']))
            event(db, 'NEW_RELEASE', repo, str(item['id']), {'tag': item['tag_name'], 'name': item.get('name')})
            found.append({'id': item['id'], 'tag': item['tag_name'], 'name': item.get('name'),
                          'published_at': item.get('published_at'), 'url': item['html_url']})
        repo.last_release_id = item['id']
    db.commit()
    return ReleasePollResult(fetched=len(rows), new_releases=tuple(found))


async def poll_all_releases(run_id: str | None = None) -> int:
    with SessionLocal() as lock_db:
        locked = lock_db.get_bind().dialect.name == 'postgresql'
        if locked and not lock_db.scalar(text('SELECT pg_try_advisory_lock(:key)'), {'key': POLL_LOCK_ID}):
            log.info('Release poll skipped because another run is active')
            if run_id:
                with SessionLocal() as db:
                    entry = db.get(Setting, LATEST_RUN_KEY)
                    if entry and entry.value.get('id') == run_id:
                        entry.value = {**entry.value, 'status': 'skipped',
                                       'completed_at': datetime.now(timezone.utc).isoformat()}
                        db.commit()
            return 0
        try:
            return await run_release_poll(run_id or uuid4().hex[:12])
        finally:
            if locked:
                lock_db.scalar(text('SELECT pg_advisory_unlock(:key)'), {'key': POLL_LOCK_ID})


def stop_requested(run_id: str) -> bool:
    with SessionLocal() as db:
        entry = db.get(Setting, LATEST_RUN_KEY)
        return bool(entry and entry.value.get('id') == run_id and entry.value.get('stop_requested'))


async def run_release_poll(run_id: str) -> int:
    started = datetime.now(timezone.utc)
    log.info('Release poll run %s started at %s', run_id, started.isoformat())
    try:
        with SessionLocal() as db:
            repo_ids = db.scalars(select(Repository.id).order_by(Repository.id)).all()
            run = {'id': run_id, 'status': 'running', 'started_at': started.isoformat(),
                   'completed_at': None, 'total_repositories': len(repo_ids),
                   'checked_count': 0, 'new_release_count': 0, 'error_count': 0,
                   'notification_status': 'pending', 'stop_requested': False, 'repositories': []}
            save_latest_run(db, run)
    except Exception:
        log.exception('Release poll run %s failed before repositories could be loaded', run_id)
        raise
    errors = 0
    added = 0
    checked = 0
    stopped = False
    rate_limit: RateLimitError | None = None
    client = GitHubClient()
    try:
        for repo_id in repo_ids:
            if stop_requested(run_id):
                stopped = True
                break
            with SessionLocal() as db:
                if rate_limit := rate_limit_error(db):
                    break
                repo = db.get(Repository, repo_id)
                if repo is None:
                    continue
                try:
                    result = await poll_releases(db, client, repo)
                    added += len(result.new_releases)
                    entry = {'repository_id': repo.id, 'repository': f'{repo.owner}/{repo.name}',
                             'status': 'checked', 'fetched': result.fetched,
                             'new_releases': list(result.new_releases), 'error': None}
                    log.info('Run %s checked %s/%s: %s releases returned, %s new',
                             run_id, repo.owner, repo.name, result.fetched, len(result.new_releases))
                    for release in result.new_releases:
                        log.info('Run %s found release in %s/%s: %s', run_id, repo.owner, repo.name,
                                 json.dumps(release, ensure_ascii=False))
                except RateLimitError as exc:
                    db.rollback()
                    record_rate_limit(db, exc)
                    rate_limit = exc
                    log.warning('Run %s stopped at %s/%s: %s', run_id, repo.owner, repo.name, exc)
                    break
                except Exception as exc:
                    db.rollback()
                    errors += 1
                    entry = {'repository_id': repo.id, 'repository': f'{repo.owner}/{repo.name}',
                             'status': 'failed', 'fetched': None, 'new_releases': [],
                             'error': str(exc) or type(exc).__name__}
                    log.exception('Run %s failed checking %s/%s', run_id, repo.owner, repo.name)
                checked += 1
                run['repositories'].append(entry)
                run['checked_count'] = checked
                run['new_release_count'] = added
                run['error_count'] = errors
            with SessionLocal() as update_db:
                save_latest_run(update_db, run)
    finally:
        await client.close()
    stopped = stopped or stop_requested(run_id)
    if rate_limit:
        run['status'], run['rate_limit_reset_at'] = 'rate_limited', rate_limit.reset_at.isoformat()
    else:
        run['status'] = 'stopped' if stopped else ('completed' if errors == 0 else 'completed_with_errors')
    run['completed_at'] = datetime.now(timezone.utc).isoformat()
    with SessionLocal() as db:
        save_latest_run(db, run)
    log.info('Release poll run %s %s at %s: %s repositories checked, %s new releases, %s errors',
             run_id, run['status'], datetime.now(timezone.utc).isoformat(), checked, added, errors)
    try:
        with SessionLocal() as db:
            preference = db.get(Setting, 'notifications')
            enabled = preference.value.get('enabled', []) if preference else ['NEW_RELEASE']
        if 'NEW_RELEASE' in enabled:
            outcome = f'{rate_limit}. Stopped after checking' if rate_limit else 'Stopped after checking' if stopped else 'Checked'
            summary = (f'{outcome} {checked} repositories. Found {added} new releases. '
                       f'{errors} checks failed. Open Repositories for details.')
            sent = await UbuntuNotificationProvider().send_text('GitHub release check finished', summary)
            run['notification_status'] = 'sent' if sent else 'unavailable'
            log.info('Run %s Ubuntu notification: %s', run_id, run['notification_status'])
        else:
            run['notification_status'] = 'disabled'
            log.info('Run %s Ubuntu notification disabled in settings', run_id)
    except Exception:
        run['notification_status'] = 'failed'
        log.exception('Run %s Ubuntu notification failed', run_id)
    with SessionLocal() as db:
        save_latest_run(db, run)
    return errors


def save_latest_run(db: Session, run: dict) -> None:
    setting = db.get(Setting, LATEST_RUN_KEY)
    if setting is None:
        db.add(Setting(key=LATEST_RUN_KEY, value=run))
    else:
        requested = setting.value.get('stop_requested', False) if setting.value.get('id') == run['id'] else False
        status = 'stopping' if requested and run['status'] == 'running' else run['status']
        setting.value = {**run, 'status': status, 'stop_requested': run.get('stop_requested', False) or requested,
                         'repositories': list(run['repositories'])}
    db.commit()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    raise SystemExit(1 if asyncio.run(poll_all_releases()) else 0)
