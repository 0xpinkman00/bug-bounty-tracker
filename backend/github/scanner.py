import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from backend.github.client import GitHubClient, normalize_github_url
from backend.models import Repository, Commit, Tag, Event, ChangedFile, now

log = logging.getLogger(__name__)

def parse_date(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace('Z', '+00:00')) if value else None

def event(db: Session, kind: str, repo: Repository, identity: str, payload: dict) -> None:
    if not db.scalar(select(Event.id).where(Event.event_type == kind, Event.repository_id == repo.id, Event.identity == identity)):
        db.add(Event(event_type=kind, repository_id=repo.id, identity=identity, payload=payload))

def classify_file(filename: str) -> tuple[str | None, bool]:
    language = 'Solidity' if filename.endswith('.sol') else 'Rust' if filename.endswith('.rs') else None
    dependency = filename.rsplit('/', 1)[-1] in {'package.json', 'package-lock.json', 'yarn.lock', 'Cargo.toml', 'Cargo.lock', 'requirements.txt', 'poetry.lock', 'foundry.toml'}
    return language, dependency

async def register_repository(db: Session, client: GitHubClient, url: str) -> Repository:
    owner, name = normalize_github_url(url)
    existing = db.scalar(select(Repository).where(Repository.owner.ilike(owner), Repository.name.ilike(name)))
    if existing:
        return existing
    data = await client.get(f'/repos/{owner}/{name}')
    assert isinstance(data, dict)
    canonical_owner = data['owner']['login']
    canonical_name = data['name']
    existing = db.scalar(select(Repository).where(Repository.github_repo_id == data['id']))
    if existing:
        return existing
    repo = Repository(github_repo_id=data['id'], owner=canonical_owner, name=canonical_name, url=data['html_url'], default_branch=data['default_branch'], archived=data['archived'], next_scan_at=now(), metadata_json={})
    db.add(repo)
    db.flush()
    event(db, 'NEW_REPOSITORY', repo, str(data['id']), {'name': data['full_name']})
    db.commit()
    return repo

async def scan_repository(db: Session, client: GitHubClient, repo: Repository) -> None:
    try:
        data = await client.get(f'/repos/{repo.owner}/{repo.name}')
        assert isinstance(data, dict)
        if repo.default_branch and repo.default_branch != data['default_branch']:
            event(db, 'DEFAULT_BRANCH_CHANGED', repo, data['default_branch'], {'previous': repo.default_branch, 'current': data['default_branch']})
        if not repo.archived and data['archived']:
            event(db, 'REPOSITORY_ARCHIVED', repo, 'archived', {})
        repo.owner, repo.name, repo.url = data['owner']['login'], data['name'], data['html_url']
        repo.github_repo_id, repo.default_branch, repo.archived = data['id'], data['default_branch'], data['archived']
        head = await client.get(f'/repos/{repo.owner}/{repo.name}/commits/{repo.default_branch}')
        assert isinstance(head, dict)
        new_sha = head['sha']
        if new_sha != repo.last_commit_sha:
            commits = await client.get(f'/repos/{repo.owner}/{repo.name}/commits', {'sha': repo.default_branch, 'per_page': 100})
            assert isinstance(commits, list)
            for item in reversed(commits):
                if item['sha'] == repo.last_commit_sha:
                    continue
                if db.scalar(select(Commit.id).where(Commit.repository_id == repo.id, Commit.sha == item['sha'])):
                    continue
                info = item['commit']
                commit = Commit(repository_id=repo.id, sha=item['sha'], message=info['message'], author=info.get('author', {}).get('name'), committed_at=parse_date(info.get('author', {}).get('date')))
                db.add(commit)
                db.flush()
                event(db, 'NEW_COMMIT', repo, item['sha'], {'sha': item['sha'], 'message': info['message'].splitlines()[0]})
                try:
                    detail = await client.get(f'/repos/{repo.owner}/{repo.name}/commits/{item["sha"]}')
                    if isinstance(detail, dict):
                        for file in detail.get('files', []):
                            language, dependency = classify_file(file['filename'])
                            db.add(ChangedFile(commit_id=commit.id, filename=file['filename'], status=file['status'], additions=file.get('additions', 0), deletions=file.get('deletions', 0), patch=file.get('patch'), language=language, dependency_change=dependency))
                except Exception:
                    log.exception('file scan failed for commit %s', item['sha'])
            repo.last_commit_sha = new_sha
        tags = await client.get(f'/repos/{repo.owner}/{repo.name}/tags', {'per_page': 100})
        assert isinstance(tags, list)
        for item in tags:
            if not db.scalar(select(Tag.id).where(Tag.repository_id == repo.id, Tag.name == item['name'])):
                db.add(Tag(repository_id=repo.id, name=item['name'], commit_sha=item['commit']['sha']))
                event(db, 'NEW_TAG', repo, item['name'], {'tag': item['name'], 'sha': item['commit']['sha']})
        repo.scan_failures = 0
        repo.last_scanned_at = now()
        repo.next_scan_at = now() + timedelta(seconds=86400 if repo.archived else repo.scan_interval)
        db.commit()
        log.info('repository scanned', extra={'repository_id': repo.id})
    except Exception:
        db.rollback()
        repo.scan_failures += 1
        repo.next_scan_at = now() + timedelta(minutes=min(60, 2 ** min(repo.scan_failures, 6)))
        db.commit()
        log.exception('repository scan failed', extra={'repository_id': repo.id})
        raise
