from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator, Literal
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select, func, case
from sqlalchemy.orm import Session
from backend.database import SessionLocal
from backend.github.client import GitHubClient, GitHubError
from backend.github.scanner import register_repository
from backend.models import Program, ProgramRepository, Repository, Commit, Release, Tag, Event, Asset, ChangedFile, Setting, SourceSyncRun, now
from backend.workers.tasks import scan_one, sync_source_run, DEFAULT_TYPES
from backend.services.discovery import SOURCE_CLASSES, create_source_run, pause_source_run, resume_source_run, stop_source_run

app = FastAPI(title='Bug Bounty Tracker')
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:5173', 'http://127.0.0.1:5173'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

def get_db() -> Iterator[Session]:
    with SessionLocal() as db:
        yield db

class RepositoryInput(BaseModel):
    url: str
    scan_interval: int | None = None

class ProgramInput(BaseModel):
    name: str
    platform: str = 'manual'
    platform_program_id: str
    program_url: str
    max_bounty: str | None = None
    status: str = 'active'

class SettingsInput(BaseModel):
    notifications: list[str] = DEFAULT_TYPES
    scan_interval: int = 3600

def page(db: Session, model: type, offset: int, limit: int, filters: list = [], order=None) -> dict:
    query = select(model)
    count = select(func.count()).select_from(model)
    for predicate in filters:
        query = query.where(predicate)
        count = count.where(predicate)
    if order is not None:
        query = query.order_by(order)
    return {'items': [serialize(item) for item in db.scalars(query.offset(offset).limit(limit))], 'total': db.scalar(count), 'offset': offset, 'limit': limit}

def serialize(obj) -> dict:
    result = {}
    for column in obj.__table__.columns:
        value = getattr(obj, obj.__mapper__.get_property_by_column(column).key)
        if isinstance(value, datetime):
            value = value.isoformat()
        result[column.name] = value
    return result

@app.get('/api/overview')
def overview(db: Session = Depends(get_db)) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    stats = {
        'programs': db.scalar(select(func.count()).select_from(Program)) or 0,
        'repositories': db.scalar(select(func.count()).select_from(Repository)) or 0,
        'releases': db.scalar(select(func.count()).select_from(Release)) or 0,
        'releases_7d': db.scalar(select(func.count()).select_from(Release).where(Release.published_at >= cutoff)) or 0,
        'unread_events': db.scalar(select(func.count()).select_from(Event).where(Event.read_at.is_(None))) or 0,
        'scan_failures': db.scalar(select(func.count()).select_from(Repository).where(Repository.scan_failures > 0)) or 0,
    }
    recent_releases = db.execute(select(Release, Repository).join(Repository, Release.repository_id == Repository.id).order_by(Release.published_at.desc().nullslast(), Release.id.desc()).limit(6)).all()
    recent_events = db.scalars(select(Event).order_by(Event.created_at.desc(), Event.id.desc()).limit(8)).all()
    repository_ids = {event.repository_id for event in recent_events if event.repository_id}
    program_ids = {event.program_id for event in recent_events if event.program_id}
    repository_names = {repo.id: f'{repo.owner}/{repo.name}' for repo in db.scalars(select(Repository).where(Repository.id.in_(repository_ids)))} if repository_ids else {}
    program_names = {program.id: program.name for program in db.scalars(select(Program).where(Program.id.in_(program_ids)))} if program_ids else {}
    return {
        'stats': stats,
        'recent_releases': [{**serialize(release), 'repository_name': f'{repo.owner}/{repo.name}'} for release, repo in recent_releases],
        'recent_events': [{**serialize(event), 'repository_name': repository_names.get(event.repository_id), 'program_name': program_names.get(event.program_id)} for event in recent_events],
        'sources': [source_summary(db, name) for name in SOURCE_CLASSES],
    }

@app.get('/api/programs')
def programs(db: Session = Depends(get_db), offset: int = 0, limit: int = Query(25, le=100), search: str = '', platform: str = '', repository: Literal['linked', 'unlinked', 'all'] = 'all') -> dict:
    filters = [Program.name.ilike(f'%{search}%')] if search else []
    if platform: filters.append(Program.platform == platform)
    has_repository = select(ProgramRepository.program_id).where(ProgramRepository.program_id == Program.id).exists()
    if repository == 'linked': filters.append(has_repository)
    if repository == 'unlinked': filters.append(~has_repository)
    latest_release = (select(func.max(Release.published_at))
                      .join(ProgramRepository, Release.repository_id == ProgramRepository.repository_id)
                      .where(ProgramRepository.program_id == Program.id)
                      .correlate(Program).scalar_subquery())
    program_update = func.coalesce(Program.last_changed_at, Program.first_seen_at)
    latest_activity = case((latest_release > program_update, latest_release), else_=program_update)
    query = select(Program, latest_activity).order_by(latest_activity.desc(), Program.id.desc())
    count = select(func.count()).select_from(Program)
    for predicate in filters:
        query = query.where(predicate)
        count = count.where(predicate)
    items = [{**serialize(program), 'latest_activity_at': activity.isoformat() if activity else None}
             for program, activity in db.execute(query.offset(offset).limit(limit))]
    return {'items': items, 'total': db.scalar(count), 'offset': offset, 'limit': limit}

@app.get('/api/programs/{program_id}')
def program_detail(program_id: int, db: Session = Depends(get_db)) -> dict:
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404)
    return {**serialize(program), 'assets': [serialize(x) for x in db.scalars(select(Asset).where(Asset.program_id == program_id))], 'repositories': [serialize(x) for x in program.repositories], 'events': [serialize(x) for x in db.scalars(select(Event).where(Event.program_id == program_id).order_by(Event.id.desc()).limit(50))], 'releases': [serialize(x) for x in db.scalars(select(Release).where(Release.repository_id.in_([r.id for r in program.repositories] or [-1])).order_by(Release.id.desc()).limit(20))]}

@app.post('/api/programs')
def create_program(body: ProgramInput, db: Session = Depends(get_db)) -> dict:
    existing = db.scalar(select(Program).where(Program.platform == body.platform, Program.platform_program_id == body.platform_program_id))
    if existing:
        return serialize(existing)
    item = Program(**body.model_dump())
    db.add(item); db.flush()
    db.add(Event(event_type='NEW_PROGRAM', program_id=item.id, identity=f'{item.platform}:{item.platform_program_id}', payload={'name': item.name}))
    db.commit()
    return serialize(item)

@app.delete('/api/programs/{program_id}')
def delete_program(program_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.get(Program, program_id)
    if not item: raise HTTPException(404)
    db.delete(item); db.commit()
    return {'ok': True}

@app.get('/api/repositories')
def repositories(db: Session = Depends(get_db), offset: int = 0, limit: int = Query(25, le=100), search: str = '') -> dict:
    filters = [(Repository.owner + '/' + Repository.name).ilike(f'%{search}%')] if search else []
    return page(db, Repository, offset, limit, filters, Repository.id.desc())

@app.get('/api/repositories/{repository_id}')
def repository_detail(repository_id: int, db: Session = Depends(get_db)) -> dict:
    repo = db.get(Repository, repository_id)
    if not repo: raise HTTPException(404)
    commits = db.scalars(select(Commit).where(Commit.repository_id == repository_id).order_by(Commit.id.desc()).limit(30)).all()
    return {**serialize(repo), 'programs': [serialize(x) for x in repo.programs], 'commits': [{**serialize(x), 'files': [serialize(f) for f in db.scalars(select(ChangedFile).where(ChangedFile.commit_id == x.id))]} for x in commits], 'releases': [serialize(x) for x in db.scalars(select(Release).where(Release.repository_id == repository_id).order_by(Release.id.desc()).limit(30))], 'tags': [serialize(x) for x in db.scalars(select(Tag).where(Tag.repository_id == repository_id).order_by(Tag.id.desc()).limit(30))], 'events': [serialize(x) for x in db.scalars(select(Event).where(Event.repository_id == repository_id).order_by(Event.id.desc()).limit(50))]}

@app.post('/api/repositories')
async def create_repository(body: RepositoryInput, db: Session = Depends(get_db)) -> dict:
    preference = db.get(Setting, 'preferences')
    interval = body.scan_interval or (preference.value.get('scan_interval', 3600) if preference else 3600)
    if interval < 300: raise HTTPException(422, 'Minimum scan interval is 300 seconds')
    client = GitHubClient()
    try:
        repo = await register_repository(db, client, body.url)
        repo.scan_interval = interval
        db.commit()
        scan_one.delay(repo.id)
        return serialize(repo)
    except (ValueError, GitHubError) as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        await client.close()

@app.post('/api/repositories/{repository_id}/scan')
def scan_now(repository_id: int, db: Session = Depends(get_db)) -> dict:
    if not db.get(Repository, repository_id): raise HTTPException(404)
    scan_one.delay(repository_id)
    return {'queued': True}

@app.delete('/api/repositories/{repository_id}')
def delete_repository(repository_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.get(Repository, repository_id)
    if not item: raise HTTPException(404)
    db.delete(item); db.commit()
    return {'ok': True}

@app.get('/api/events')
def events(db: Session = Depends(get_db), offset: int = 0, limit: int = Query(25, le=100), event_type: str = '', search: str = '') -> dict:
    filters = [Event.event_type == event_type] if event_type else []
    if search: filters.append(Event.payload.cast(__import__('sqlalchemy').String).ilike(f'%{search}%'))
    result = page(db, Event, offset, limit, filters, Event.id.desc())
    repository_ids = {item['repository_id'] for item in result['items'] if item['repository_id']}
    program_ids = {item['program_id'] for item in result['items'] if item['program_id']}
    repository_names = {repo.id: f'{repo.owner}/{repo.name}' for repo in db.scalars(select(Repository).where(Repository.id.in_(repository_ids)))} if repository_ids else {}
    program_names = {program.id: program.name for program in db.scalars(select(Program).where(Program.id.in_(program_ids)))} if program_ids else {}
    for item in result['items']:
        item['repository_name'] = repository_names.get(item['repository_id'])
        item['program_name'] = program_names.get(item['program_id'])
    return result

@app.get('/api/events/{event_id}')
def event_detail(event_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.get(Event, event_id)
    if not item: raise HTTPException(404)
    return serialize(item)

@app.post('/api/events/{event_id}/read')
def mark_read(event_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.get(Event, event_id)
    if not item: raise HTTPException(404)
    item.read_at = now(); db.commit()
    return serialize(item)

@app.get('/api/releases')
def releases(db: Session = Depends(get_db), offset: int = 0, limit: int = Query(25, le=100)) -> dict:
    rows = db.execute(select(Release, Repository).join(Repository, Release.repository_id == Repository.id).order_by(Release.published_at.desc().nullslast(), Release.id.desc()).offset(offset).limit(limit)).all()
    total = db.scalar(select(func.count()).select_from(Release)) or 0
    return {'items': [{**serialize(release), 'repository_name': f'{repo.owner}/{repo.name}'} for release, repo in rows], 'total': total, 'offset': offset, 'limit': limit}

@app.get('/api/releases/latest-run')
def latest_release_run(db: Session = Depends(get_db)) -> dict | None:
    entry = db.get(Setting, 'latest_release_poll')
    return entry.value if entry else None

def serialize_source_run(run: SourceSyncRun) -> dict:
    result = serialize(run)
    result.pop('program_ids', None)
    return result

def source_summary(db: Session, name: str) -> dict:
    latest = db.scalar(select(SourceSyncRun).where(SourceSyncRun.source == name).order_by(SourceSyncRun.id.desc()))
    count = db.scalar(select(func.count()).select_from(Program).where(Program.platform == name)) or 0
    return {'name': name, 'program_count': count, 'latest_run': serialize_source_run(latest) if latest else None}

@app.get('/api/sources')
def sources(db: Session = Depends(get_db)) -> dict:
    return {'items': [source_summary(db, name) for name in SOURCE_CLASSES]}

@app.get('/api/sources/{source_name}')
def source_detail(source_name: str, db: Session = Depends(get_db)) -> dict:
    if source_name not in SOURCE_CLASSES: raise HTTPException(404, 'Unknown source')
    runs = db.scalars(select(SourceSyncRun).where(SourceSyncRun.source == source_name).order_by(SourceSyncRun.id.desc()).limit(20)).all()
    return {**source_summary(db, source_name), 'runs': [serialize_source_run(run) for run in runs]}

@app.post('/api/sources/{source_name}/sync')
def trigger_source_sync(source_name: str, db: Session = Depends(get_db)) -> dict:
    if source_name not in SOURCE_CLASSES: raise HTTPException(404, 'Unknown source')
    run, created = create_source_run(db, source_name)
    if created:
        try:
            sync_source_run.delay(run.id)
        except Exception as exc:
            run.status = 'failed'
            run.last_error = 'Could not queue sync job'
            run.completed_at = now()
            db.commit()
            raise HTTPException(503, 'Could not queue sync job') from exc
    return serialize_source_run(run)

@app.get('/api/source-syncs/{run_id}')
def source_sync_detail(run_id: int, db: Session = Depends(get_db)) -> dict:
    run = db.get(SourceSyncRun, run_id)
    if not run: raise HTTPException(404)
    return serialize_source_run(run)

def get_source_run(db: Session, run_id: int) -> SourceSyncRun:
    run = db.get(SourceSyncRun, run_id)
    if not run: raise HTTPException(404)
    return run

@app.post('/api/source-syncs/{run_id}/pause')
def pause_source_sync(run_id: int, db: Session = Depends(get_db)) -> dict:
    try:
        return serialize_source_run(pause_source_run(db, get_source_run(db, run_id)))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc

@app.post('/api/source-syncs/{run_id}/resume')
def resume_source_sync(run_id: int, db: Session = Depends(get_db)) -> dict:
    try:
        run = resume_source_run(db, get_source_run(db, run_id))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    try:
        sync_source_run.delay(run.id)
    except Exception as exc:
        run.status = 'paused'
        db.commit()
        raise HTTPException(503, 'Could not queue resume job') from exc
    return serialize_source_run(run)

@app.post('/api/source-syncs/{run_id}/stop')
def stop_source_sync(run_id: int, db: Session = Depends(get_db)) -> dict:
    try:
        return serialize_source_run(stop_source_run(db, get_source_run(db, run_id)))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc

@app.get('/api/settings')
def settings(db: Session = Depends(get_db)) -> dict:
    record = db.get(Setting, 'preferences')
    return record.value if record else SettingsInput().model_dump()

@app.put('/api/settings')
def save_settings(body: SettingsInput, db: Session = Depends(get_db)) -> dict:
    record = db.get(Setting, 'preferences')
    if record: record.value = body.model_dump()
    else: db.add(Setting(key='preferences', value=body.model_dump()))
    notifications = db.get(Setting, 'notifications')
    if notifications: notifications.value = {'enabled': body.notifications}
    else: db.add(Setting(key='notifications', value={'enabled': body.notifications}))
    db.commit()
    return body.model_dump()
