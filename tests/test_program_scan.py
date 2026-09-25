import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import backend.main as main
from backend.database import Base
from backend.main import program_scan_status, serialize_assets, start_program_scan
from backend.models import Asset, Program, ProgramRepository, ProgramUpdate, Release, Repository
from backend.services import discovery, program_scan
from backend.sources.base import SourceProgram
from tests.test_scanner import FakeGitHub


class Client(FakeGitHub):
    async def close(self):
        pass


@pytest.mark.asyncio
async def test_program_scan_refreshes_program_and_checks_its_repositories(monkeypatch) -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)

    class Source:
        async def get_program(self, identifier):
            return SourceProgram('immunefi', identifier, 'Renamed', 'https://example.com', max_bounty='$1,000',
                                 repositories=['https://github.com/org/repo'])
        async def close(self):
            pass

    queued = []

    class Task:
        def delay(self, program_id, run):
            queued.append((program_id, run))

    monkeypatch.setattr(main, 'scan_program_now', Task())
    monkeypatch.setattr(program_scan, 'SessionLocal', factory)
    monkeypatch.setattr(program_scan, 'GitHubClient', Client)
    monkeypatch.setattr(discovery, 'SOURCE_CLASSES', {'immunefi': Source})

    with factory() as db:
        await discovery.save_program(db, Client(), SourceProgram('immunefi', 'demo', 'Demo', 'https://example.com'))
        program_id = db.scalar(select(Program.id))
        assert program_scan_status(program_id, db) is None
        run = start_program_scan(program_id, db)
        assert queued == [(program_id, run)]
        with pytest.raises(HTTPException) as duplicate:
            start_program_scan(program_id, db)
        assert duplicate.value.status_code == 409

    result = await program_scan.scan_program(program_id, run)
    assert result['status'] == 'completed'
    assert result['program_updated'] is True
    assert (result['total_repositories'], result['checked_count'], result['new_release_count']) == (1, 1, 1)

    with factory() as db:
        assert db.get(Program, program_id).name == 'Renamed'
        assert db.scalar(select(ProgramUpdate.id)) is not None
        assert db.scalar(select(ProgramRepository.repository_id)) == db.scalar(select(Repository.id))
        assert db.scalar(select(Repository.last_commit_sha)) == 'abc'
        assert db.scalar(select(Release.tag)) == 'v1'
        assert program_scan_status(program_id, db)['status'] == 'completed'

    with factory() as db:
        program = db.get(Program, program_id)
        db.add_all([Asset(program_id=program_id, type='smart_contract', value='Vault', url='https://github.com/ORG/repo/blob/main/Vault.sol', in_scope=True),
                    Asset(program_id=program_id, type='website', value='https://example.com', url=None, in_scope=True)])
        db.commit()
        assets = {asset['type']: asset for asset in serialize_assets(db, program)}
        assert assets['smart_contract']['latest_release']['tag'] == 'v1'
        assert assets['website']['repository_id'] is None and assets['website']['latest_release'] is None
