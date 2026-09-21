"""Daily GitHub release polling, independent of the regular repository scan."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.github.client import GitHubClient
from backend.github.scanner import event, parse_date
from backend.models import Release, Repository, Setting

log = logging.getLogger(__name__)
LATEST_RUN_KEY = 'latest_release_poll'


@dataclass(frozen=True)
class ReleasePollResult:
    fetched: int
    new_releases: tuple[dict, ...]


async def poll_releases(db: Session, client: GitHubClient, repo: Repository) -> ReleasePollResult:
    rows = await client.get(f'/repos/{repo.owner}/{repo.name}/releases', {'per_page': 100})
    if not isinstance(rows, list):
        raise ValueError(f'Unexpected releases response for {repo.owner}/{repo.name}')
    found = []
    for item in rows:
        if db.scalar(select(Release.id).where(Release.repository_id == repo.id,
                                             Release.github_release_id == item['id'])):
            continue
        db.add(Release(repository_id=repo.id, github_release_id=item['id'], tag=item['tag_name'],
                       name=item.get('name'), commit_sha=None, published_at=parse_date(item.get('published_at')),
                       release_url=item['html_url']))
        event(db, 'NEW_RELEASE', repo, str(item['id']), {'tag': item['tag_name'], 'name': item.get('name')})
        found.append({'id': item['id'], 'tag': item['tag_name'], 'name': item.get('name'),
                      'published_at': item.get('published_at'), 'url': item['html_url']})
    if rows:
        repo.last_release_id = rows[0]['id']
    db.commit()
    return ReleasePollResult(fetched=len(rows), new_releases=tuple(found))


async def poll_all_releases() -> int:
    run_id = uuid4().hex[:12]
    started = datetime.now(timezone.utc)
    log.info('Release poll run %s started at %s', run_id, started.isoformat())
    try:
        with SessionLocal() as db:
            repo_ids = db.scalars(select(Repository.id).order_by(Repository.id)).all()
            run = {'id': run_id, 'status': 'running', 'started_at': started.isoformat(),
                   'completed_at': None, 'total_repositories': len(repo_ids),
                   'checked_count': 0, 'new_release_count': 0, 'error_count': 0, 'repositories': []}
            save_latest_run(db, run)
    except Exception:
        log.exception('Release poll run %s failed before repositories could be loaded', run_id)
        raise
    errors = 0
    added = 0
    checked = 0
    client = GitHubClient()
    try:
        for repo_id in repo_ids:
            with SessionLocal() as db:
                repo = db.get(Repository, repo_id)
                if repo is None:
                    continue
                checked += 1
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
                except Exception as exc:
                    db.rollback()
                    errors += 1
                    entry = {'repository_id': repo.id, 'repository': f'{repo.owner}/{repo.name}',
                             'status': 'failed', 'fetched': None, 'new_releases': [],
                             'error': str(exc) or type(exc).__name__}
                    log.exception('Run %s failed checking %s/%s', run_id, repo.owner, repo.name)
                run['repositories'].append(entry)
                run['checked_count'] = checked
                run['new_release_count'] = added
                run['error_count'] = errors
            with SessionLocal() as update_db:
                save_latest_run(update_db, run)
    finally:
        await client.close()
    run['status'] = 'completed' if errors == 0 else 'completed_with_errors'
    run['completed_at'] = datetime.now(timezone.utc).isoformat()
    with SessionLocal() as db:
        save_latest_run(db, run)
    log.info('Release poll run %s finished at %s: %s repositories checked, %s new releases, %s errors',
             run_id, datetime.now(timezone.utc).isoformat(), checked, added, errors)
    return errors


def save_latest_run(db: Session, run: dict) -> None:
    setting = db.get(Setting, LATEST_RUN_KEY)
    if setting is None:
        db.add(Setting(key=LATEST_RUN_KEY, value=run))
    else:
        setting.value = {**run, 'repositories': list(run['repositories'])}
    db.commit()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    raise SystemExit(1 if asyncio.run(poll_all_releases()) else 0)
