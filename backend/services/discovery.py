import hashlib
import json
import logging
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session
from backend.database import SessionLocal
from backend.github.client import GitHubClient, RateLimitError
from backend.github.ratelimit import rate_limit_error, record_rate_limit
from backend.github.scanner import register_repository
from backend.models import Asset, Event, Program, ProgramRepository, ProgramSnapshot, ProgramUpdate, SourceSyncRun, now
from backend.sources.base import SourceProgram
from backend.sources.immunefi import ImmunefiSource
from backend.sources.hackenproof import HackenProofSource

log = logging.getLogger(__name__)

def _unique(items: list[dict]) -> list[dict]:
    return [json.loads(item) for item in sorted({json.dumps(entry, sort_keys=True) for entry in items})]

def normalize_program(program: SourceProgram) -> dict:
    return {'name': program.name.strip(), 'platform': program.platform.lower(), 'platform_program_id': program.platform_program_id.strip(), 'program_url': program.program_url, 'max_bounty': program.max_bounty, 'status': program.status, 'assets': sorted([{'type': a.type, 'value': a.value.strip(), 'url': a.url, 'in_scope': a.in_scope} for a in program.assets], key=lambda a: (a['type'], a['value'])), 'repositories': sorted(program.repositories),
            'impacts': _unique(program.impacts), 'known_issues': _unique(program.known_issues)}

# Order in which update categories are listed.
UPDATE_CATEGORIES = ('scope', 'max_bounty', 'impacts', 'known_issues', 'details')

def _list_change(previous: list[dict], current: list[dict]) -> dict | None:
    before = {json.dumps(item, sort_keys=True) for item in previous}
    after = {json.dumps(item, sort_keys=True) for item in current}
    if before == after:
        return None
    return {'added': [json.loads(item) for item in sorted(after - before)], 'removed': [json.loads(item) for item in sorted(before - after)]}

def diff_programs(previous: dict, current: dict) -> dict:
    """What changed between two normalized snapshots, keyed by UPDATE_CATEGORIES.

    A category missing from the previous snapshot was not collected yet, so its first value is a baseline, not a change.
    """
    changes = {}
    added, removed = compare_snapshots(previous, current)
    if added or removed:
        changes['scope'] = {'added': [{'type': t, 'value': v} for t, v in sorted(added)], 'removed': [{'type': t, 'value': v} for t, v in sorted(removed)]}
    legacy = 'impacts' not in previous
    if previous.get('max_bounty') != current.get('max_bounty') and not (legacy and previous.get('max_bounty') is None):
        changes['max_bounty'] = {'before': previous.get('max_bounty'), 'after': current.get('max_bounty')}
    for key in ('impacts', 'known_issues'):
        if key in previous and (change := _list_change(previous[key], current.get(key, []))):
            changes[key] = change
    details = {key: {'before': previous.get(key), 'after': current.get(key)} for key in ('name', 'status', 'program_url') if key in previous and previous[key] != current.get(key)}
    if details:
        changes['details'] = details
    return changes

def compare_snapshots(previous: dict, current: dict) -> tuple[set[tuple[str,str]], set[tuple[str,str]]]:
    def identities(data: dict) -> set[tuple[str,str]]:
        return {(a['type'], a['value']) for a in data.get('assets', []) if a.get('in_scope', True)}
    return identities(current) - identities(previous), identities(previous) - identities(current)

async def save_program(db: Session, client: GitHubClient, source: SourceProgram) -> tuple[Program, list[str], ProgramUpdate | None]:
    data = normalize_program(source)
    program = db.scalar(select(Program).where(Program.platform == data['platform'], Program.platform_program_id == data['platform_program_id']))
    fresh = program is None
    if fresh:
        program = Program(name=data['name'], platform=data['platform'], platform_program_id=data['platform_program_id'], program_url=data['program_url'], max_bounty=data['max_bounty'], status=data['status'])
        db.add(program)
        db.flush()
        db.add(Event(event_type='NEW_PROGRAM', program_id=program.id, identity=f'{program.platform}:{program.platform_program_id}', payload={'name': program.name}))
    previous = db.scalar(select(ProgramSnapshot).where(ProgramSnapshot.program_id == program.id).order_by(ProgramSnapshot.id.desc()))
    raw = json.dumps(data, sort_keys=True)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    program_update = None
    if not previous or previous.content_hash != digest:
        added, removed = compare_snapshots(previous.raw_data if previous else {}, data)
        changes = diff_programs(previous.raw_data, data) if previous else {}
        if changes:
            categories = [category for category in UPDATE_CATEGORIES if category in changes]
            program_update = ProgramUpdate(program_id=program.id, categories=categories, changes=changes)
            db.add(program_update); db.flush()
            db.add(Event(event_type='PROGRAM_UPDATED', program_id=program.id, identity=digest, payload={'name': data['name'], 'update_id': program_update.id, 'categories': categories}))
            program.last_changed_at = now()
        for kind, entries in [('SCOPE_ADDED', added), ('SCOPE_REMOVED', removed)]:
            for asset_type, value in entries:
                db.add(Event(event_type=kind, program_id=program.id, identity=f'{digest}:{kind}:{asset_type}:{value}'[:255], payload={'type': asset_type, 'value': value}))
        for asset_type, value in added:
            asset = db.scalar(select(Asset).where(Asset.program_id == program.id, Asset.type == asset_type, Asset.value == value))
            if asset:
                asset.in_scope = True
            else:
                db.add(Asset(program_id=program.id, type=asset_type, value=value, url=next((a['url'] for a in data['assets'] if a['value'] == value), None), in_scope=True))
        for asset_type, value in removed:
            asset = db.scalar(select(Asset).where(Asset.program_id == program.id, Asset.type == asset_type, Asset.value == value))
            if asset:
                asset.in_scope = False
        db.add(ProgramSnapshot(program_id=program.id, content_hash=digest, raw_data=data))
    program.name, program.program_url, program.max_bounty, program.status = data['name'], data['program_url'], data['max_bounty'], data['status']
    program.last_seen_at = now()
    db.commit()
    failures: list[str] = []
    for url in data['repositories']:
        try:
            repo = await register_repository(db, client, url)
            if not db.get(ProgramRepository, (program.id, repo.id)):
                db.add(ProgramRepository(program_id=program.id, repository_id=repo.id, discovered_from='scope'))
                db.commit()
        except RateLimitError:
            db.rollback()
            raise
        except Exception as exc:
            db.rollback()
            # Reported to the caller: a run that registers nothing must not look clean.
            failures.append(f'{url}: {exc or type(exc).__name__}')
            log.exception('repository registration failed', extra={'program_id': program.id, 'url': url})
    return program, failures, program_update

SOURCE_CLASSES = {'immunefi': ImmunefiSource, 'hackenproof': HackenProofSource}
ACTIVE_STATUSES = ('queued', 'running', 'pausing', 'paused', 'stopping')

def create_source_run(db: Session, source_name: str) -> tuple[SourceSyncRun, bool]:
    if source_name not in SOURCE_CLASSES:
        raise ValueError('Unknown source')
    active = db.scalar(select(SourceSyncRun).where(SourceSyncRun.source == source_name, SourceSyncRun.status.in_(ACTIVE_STATUSES)).order_by(SourceSyncRun.id.desc()))
    if active:
        return active, False
    run = SourceSyncRun(source=source_name, status='queued')
    db.add(run)
    db.commit()
    db.refresh(run)
    return run, True

def _change_status(db: Session, run: SourceSyncRun, current: tuple[str, ...], target: str, *, finish: bool = False) -> bool:
    values = {'status': target}
    if finish:
        values['completed_at'] = now()
    result = db.execute(update(SourceSyncRun).where(SourceSyncRun.id == run.id, SourceSyncRun.status.in_(current)).values(**values))
    db.commit()
    db.refresh(run)
    return result.rowcount == 1

def pause_source_run(db: Session, run: SourceSyncRun) -> SourceSyncRun:
    if _change_status(db, run, ('queued',), 'paused'):
        return run
    if _change_status(db, run, ('running',), 'pausing'):
        return run
    if run.status not in ('pausing', 'paused'):
        raise ValueError('Only a queued or running scrape can be paused')
    return run

def resume_source_run(db: Session, run: SourceSyncRun) -> SourceSyncRun:
    if not _change_status(db, run, ('paused',), 'queued'):
        raise ValueError('Only a paused scrape can be resumed')
    return run

def stop_source_run(db: Session, run: SourceSyncRun) -> SourceSyncRun:
    if _change_status(db, run, ('queued', 'paused'), 'stopped', finish=True):
        return run
    if _change_status(db, run, ('running', 'pausing'), 'stopping'):
        return run
    if run.status not in ('stopping', 'stopped'):
        raise ValueError('This scrape has already finished')
    return run

def checkpoint_run(db: Session, run_id: int) -> bool:
    run = db.get(SourceSyncRun, run_id)
    if run is None:
        return False
    if run.status == 'pausing':
        run.status = 'paused'
        db.commit()
        return False
    if run.status == 'stopping':
        run.status = 'stopped'
        run.completed_at = now()
        db.commit()
        return False
    return run.status == 'running'

async def synchronize_source_run(run_id: int) -> None:
    with SessionLocal() as db:
        claim = db.execute(update(SourceSyncRun).where(SourceSyncRun.id == run_id, SourceSyncRun.status == 'queued').values(status='running', started_at=func.coalesce(SourceSyncRun.started_at, now())))
        db.commit()
        if claim.rowcount != 1:
            return
        run = db.get(SourceSyncRun, run_id)
        source_name = run.source
    source = SOURCE_CLASSES[source_name]()
    client = GitHubClient()
    try:
        with SessionLocal() as db:
            if not checkpoint_run(db, run_id):
                return
            run = db.get(SourceSyncRun, run_id)
            identifiers = run.program_ids or []
        if not identifiers:
            identifiers = await source.list_programs()
            with SessionLocal() as db:
                run = db.get(SourceSyncRun, run_id)
                run.program_ids = identifiers
                run.discovered_count = len(identifiers)
                db.commit()
        with SessionLocal() as db:
            if not checkpoint_run(db, run_id):
                return
            next_index = db.get(SourceSyncRun, run_id).next_index
        for index in range(next_index, len(identifiers)):
            with SessionLocal() as db:
                if not checkpoint_run(db, run_id):
                    return
            identifier = identifiers[index]
            try:
                with SessionLocal() as db:
                    if limit := rate_limit_error(db):
                        raise limit
                program = await source.get_program(identifier)
                with SessionLocal() as db:
                    existing = db.scalar(select(Program.id).where(Program.platform == program.platform.lower(), Program.platform_program_id == program.platform_program_id.strip()))
                    saved, repository_failures, program_update = await save_program(db, client, program)
                    run = db.get(SourceSyncRun, run_id)
                    run.processed_count += 1
                    run.next_index = index + 1
                    if existing is None:
                        run.created_count += 1
                    elif program_update is not None:
                        run.updated_count += 1
                    if repository_failures:
                        run.error_count += len(repository_failures)
                        run.last_error = repository_failures[-1][:500]
                    db.commit()
            except RateLimitError as exc:
                # Pause on this program so Resume retries it once the limit resets.
                log.warning('source synchronization paused: %s', exc)
                with SessionLocal() as db:
                    record_rate_limit(db, exc)
                    run = db.get(SourceSyncRun, run_id)
                    run.status = 'paused'
                    run.last_error = f'{exc}. Resume the scan after the limit resets.'
                    db.commit()
                return
            except Exception as exc:
                log.exception('program synchronization failed', extra={'source': source_name, 'program_id': identifier})
                with SessionLocal() as db:
                    run = db.get(SourceSyncRun, run_id)
                    run.error_count += 1
                    run.next_index = index + 1
                    run.last_error = f'{identifier}: {str(exc)[:500]}'
                    db.commit()
        with SessionLocal() as db:
            if checkpoint_run(db, run_id):
                run = db.get(SourceSyncRun, run_id)
                run.status = 'completed'
                run.completed_at = now()
                db.commit()
    except Exception as exc:
        log.exception('source synchronization failed', extra={'source': source_name})
        with SessionLocal() as db:
            if checkpoint_run(db, run_id):
                run = db.get(SourceSyncRun, run_id)
                run.status = 'failed'
                run.last_error = str(exc)[:500]
                run.completed_at = now()
                db.commit()
        raise
    finally:
        await source.close()
        await client.close()
