import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from backend import main
from backend.database import Base
from backend.main import ProgramInput, create_program, programs
from backend.models import Program, ProgramRepository, Repository

@pytest.fixture
def db():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

@pytest.fixture
def github(monkeypatch):
    queued = []
    class Client:
        async def close(self): pass
    async def register(db, client, url):
        owner, name = url.rstrip('/').split('/')[-2:]
        repo = Repository(owner=owner, name=name, url=url)
        db.add(repo); db.flush()
        return repo
    monkeypatch.setattr(main, 'GitHubClient', Client)
    monkeypatch.setattr(main, 'register_repository', register)
    monkeypatch.setattr(main.scan_one, 'delay', queued.append)
    return queued

async def test_manual_program_links_repositories(db, github) -> None:
    body = ProgramInput(name=' Acme ', platform='Sherlock', program_url='https://audits.sherlock.xyz/acme', max_bounty='',
                        repositories=['https://github.com/acme/core', 'https://github.com/acme/core', ' '])
    result = await create_program(body, db)
    assert (result['name'], result['platform'], result['platform_program_id'], result['max_bounty']) == ('Acme', 'sherlock', 'https://audits.sherlock.xyz/acme', None)
    links = db.scalars(select(ProgramRepository)).all()
    assert [(link.program_id, link.discovered_from) for link in links] == [(result['id'], 'manual')]
    assert github == [links[0].repository_id]

async def test_manual_program_rejects_duplicates_and_source_platforms(db, github) -> None:
    await create_program(ProgramInput(name='Acme', program_url='https://acme.example'), db)
    with pytest.raises(HTTPException) as duplicate:
        await create_program(ProgramInput(name='Acme again', program_url='https://acme.example'), db)
    assert duplicate.value.status_code == 409
    with pytest.raises(HTTPException) as source:
        await create_program(ProgramInput(name='Acme', platform='Immunefi', program_url='https://immunefi.com/acme'), db)
    assert source.value.status_code == 422

def test_other_filter_excludes_synced_sources(db) -> None:
    for platform in ('immunefi', 'hackenproof', 'manual', 'sherlock'):
        db.add(Program(name=platform, platform=platform, platform_program_id=platform, program_url='https://example.com'))
    db.commit()
    names = lambda platform: sorted(item['name'] for item in programs(db, 0, 25, '', platform, 'all')['items'])
    assert names('other') == ['manual', 'sherlock']
    assert names('immunefi') == ['immunefi']
