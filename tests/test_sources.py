import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from backend.database import Base
from backend.models import Program, SourceSyncRun
from backend.sources.base import SourceProgram
from backend.services import discovery

class FakeSource:
    calls: list[str] = []
    async def list_programs(self) -> list[str]:
        self.calls.append('list')
        return ['one', 'broken']
    async def get_program(self, identifier: str) -> SourceProgram:
        self.calls.append(identifier)
        if identifier == 'broken':
            raise ValueError('sample parse error')
        return SourceProgram('immunefi', identifier, 'Example', 'https://example.com')
    async def close(self) -> None:
        pass

class FakeClient:
    async def close(self) -> None:
        pass

@pytest.mark.asyncio
async def test_chosen_source_only_and_run_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    FakeSource.calls = []
    monkeypatch.setattr(discovery, 'SessionLocal', factory)
    monkeypatch.setattr(discovery, 'GitHubClient', FakeClient)
    monkeypatch.setattr(discovery, 'SOURCE_CLASSES', {'immunefi': FakeSource, 'hackenproof': lambda: (_ for _ in ()).throw(AssertionError('wrong source'))})
    with factory() as db:
        run, created = discovery.create_source_run(db, 'immunefi')
        repeated, new = discovery.create_source_run(db, 'immunefi')
        assert created and not new and repeated.id == run.id
    await discovery.synchronize_source_run(run.id)
    with factory() as db:
        stored = db.get(SourceSyncRun, run.id)
        assert stored.status == 'completed'
        assert (stored.discovered_count, stored.processed_count, stored.created_count, stored.error_count) == (2, 1, 1, 1)
        assert len(db.scalars(select(Program)).all()) == 1
    assert FakeSource.calls == ['list', 'one', 'broken']

@pytest.mark.asyncio
async def test_pause_resume_keeps_program_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    run_id = 0
    calls: list[str] = []
    class PausingSource:
        async def list_programs(self) -> list[str]:
            calls.append('list')
            return ['one', 'two']
        async def get_program(self, identifier: str) -> SourceProgram:
            calls.append(identifier)
            if identifier == 'one':
                with factory() as db:
                    discovery.pause_source_run(db, db.get(SourceSyncRun, run_id))
            return SourceProgram('immunefi', identifier, identifier, 'https://example.com')
        async def close(self) -> None:
            pass
    monkeypatch.setattr(discovery, 'SessionLocal', factory)
    monkeypatch.setattr(discovery, 'GitHubClient', FakeClient)
    monkeypatch.setattr(discovery, 'SOURCE_CLASSES', {'immunefi': PausingSource})
    with factory() as db:
        run, _ = discovery.create_source_run(db, 'immunefi')
        run_id = run.id
    await discovery.synchronize_source_run(run_id)
    with factory() as db:
        run = db.get(SourceSyncRun, run_id)
        assert run.status == 'paused'
        assert run.next_index == 1 and run.program_ids == ['one', 'two']
        discovery.resume_source_run(db, run)
    await discovery.synchronize_source_run(run_id)
    with factory() as db:
        run = db.get(SourceSyncRun, run_id)
        assert run.status == 'completed'
        assert run.next_index == 2 and run.created_count == 2
    assert calls == ['list', 'one', 'two']

@pytest.mark.asyncio
async def test_stop_prevents_next_program(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    run_id = 0
    calls: list[str] = []
    class StoppingSource:
        async def list_programs(self) -> list[str]:
            return ['one', 'two']
        async def get_program(self, identifier: str) -> SourceProgram:
            calls.append(identifier)
            with factory() as db:
                discovery.stop_source_run(db, db.get(SourceSyncRun, run_id))
            return SourceProgram('immunefi', identifier, identifier, 'https://example.com')
        async def close(self) -> None:
            pass
    monkeypatch.setattr(discovery, 'SessionLocal', factory)
    monkeypatch.setattr(discovery, 'GitHubClient', FakeClient)
    monkeypatch.setattr(discovery, 'SOURCE_CLASSES', {'immunefi': StoppingSource})
    with factory() as db:
        run, _ = discovery.create_source_run(db, 'immunefi')
        run_id = run.id
    await discovery.synchronize_source_run(run_id)
    with factory() as db:
        run = db.get(SourceSyncRun, run_id)
        assert run.status == 'stopped'
        assert run.next_index == 1 and run.processed_count == 1
        assert run.completed_at is not None
    assert calls == ['one']

def test_queued_run_can_pause_resume_and_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(discovery, 'SOURCE_CLASSES', {'immunefi': FakeSource})
    with Session(engine, expire_on_commit=False) as db:
        run, _ = discovery.create_source_run(db, 'immunefi')
        assert discovery.pause_source_run(db, run).status == 'paused'
        duplicate, created = discovery.create_source_run(db, 'immunefi')
        assert not created and duplicate.id == run.id
        assert discovery.resume_source_run(db, run).status == 'queued'
        assert discovery.stop_source_run(db, run).status == 'stopped'
        with pytest.raises(ValueError):
            discovery.resume_source_run(db, run)
