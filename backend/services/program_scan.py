"""On-demand scan of a single program: refresh it from its source, then check its repositories."""
import logging
from datetime import datetime, timezone
from sqlalchemy import select
from backend.database import SessionLocal
from backend.github.client import GitHubClient, RateLimitError
from backend.github.ratelimit import rate_limit_error, record_rate_limit
from backend.github.releases import poll_releases
from backend.github.scanner import scan_repository
from backend.models import Program, ProgramRepository, Repository, Setting
from backend.services import discovery

log = logging.getLogger(__name__)
ACTIVE_STATUSES = ('queued', 'running')

def run_key(program_id: int) -> str:
    return f'program_scan:{program_id}'

def save_run(program_id: int, run: dict) -> None:
    with SessionLocal() as db:
        entry = db.get(Setting, run_key(program_id))
        if entry is None:
            db.add(Setting(key=run_key(program_id), value=dict(run)))
        else:
            entry.value = dict(run)
        db.commit()

async def scan_program(program_id: int, run: dict) -> dict:
    run = {**run, 'status': 'running', 'errors': list(run.get('errors', []))}
    save_run(program_id, run)
    client = GitHubClient()
    rate_limit: RateLimitError | None = None
    try:
        with SessionLocal() as db:
            program = db.get(Program, program_id)
            platform, identifier = (program.platform, program.platform_program_id) if program else (None, None)
        source_class = discovery.SOURCE_CLASSES.get(platform or '')
        if source_class:
            source = source_class()
            try:
                if rate_limit := rate_limit_error_now():
                    raise rate_limit
                fetched = await source.get_program(identifier)
                with SessionLocal() as db:
                    _, failures, update = await discovery.save_program(db, client, fetched)
                run['program_updated'] = update is not None
                run['errors'] += failures
            except RateLimitError as exc:
                rate_limit = exc
            except Exception as exc:
                log.exception('program refresh failed', extra={'program_id': program_id})
                run['errors'].append(f'{platform}: {exc or type(exc).__name__}')
            finally:
                await source.close()
        with SessionLocal() as db:
            repo_ids = db.scalars(select(ProgramRepository.repository_id).where(ProgramRepository.program_id == program_id).order_by(ProgramRepository.repository_id)).all()
        run['total_repositories'] = len(repo_ids)
        save_run(program_id, run)
        for repo_id in repo_ids:
            if rate_limit:
                break
            with SessionLocal() as db:
                if rate_limit := rate_limit_error(db):
                    break
                repo = db.get(Repository, repo_id)
                if repo is None:
                    continue
                name = f'{repo.owner}/{repo.name}'
                try:
                    await scan_repository(db, client, repo)
                    result = await poll_releases(db, client, repo)
                    run['new_release_count'] += len(result.new_releases)
                except RateLimitError as exc:
                    db.rollback()
                    rate_limit = exc
                    break
                except Exception as exc:
                    db.rollback()
                    run['errors'].append(f'{name}: {exc or type(exc).__name__}')
            run['checked_count'] += 1
            save_run(program_id, run)
    finally:
        await client.close()
    if rate_limit:
        with SessionLocal() as db:
            record_rate_limit(db, rate_limit)
        run['status'], run['rate_limit_reset_at'] = 'rate_limited', rate_limit.reset_at.isoformat()
    else:
        run['status'] = 'completed_with_errors' if run['errors'] else 'completed'
    run['completed_at'] = datetime.now(timezone.utc).isoformat()
    save_run(program_id, run)
    return run

def rate_limit_error_now() -> RateLimitError | None:
    with SessionLocal() as db:
        return rate_limit_error(db)
