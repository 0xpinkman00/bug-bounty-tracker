import pytest
from bs4 import BeautifulSoup
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from backend.database import Base
from backend.main import program_detail, programs
from backend.models import Event, ProgramUpdate
from backend.services.discovery import diff_programs, normalize_program, save_program
from backend.sources import hackenproof
from backend.sources.base import SourceAsset, SourceProgram

def source(**changes) -> SourceProgram:
    values = dict(max_bounty='$50,000', assets=[SourceAsset('website', 'https://a.example')],
                  impacts=[{'type': 'smart_contract', 'severity': 'critical', 'title': 'Theft of funds'}],
                  known_issues=[{'description': 'Rounding in fees', 'link': None}])
    return SourceProgram('immunefi', 'acme', 'Acme', 'https://immunefi.com/acme', **{**values, **changes})

class Client:
    async def close(self) -> None: pass

def test_diff_names_each_changed_part() -> None:
    before = normalize_program(source())
    after = normalize_program(source(max_bounty='$100,000', assets=[SourceAsset('website', 'https://b.example')],
                                     impacts=[{'type': 'smart_contract', 'severity': 'high', 'title': 'Theft of funds'}],
                                     known_issues=[{'description': 'Rounding in fees', 'link': None}]))
    changes = diff_programs(before, after)
    assert sorted(changes) == ['impacts', 'max_bounty', 'scope']
    assert changes['max_bounty'] == {'before': '$50,000', 'after': '$100,000'}
    assert changes['scope'] == {'added': [{'type': 'website', 'value': 'https://b.example'}], 'removed': [{'type': 'website', 'value': 'https://a.example'}]}
    assert [item['severity'] for item in changes['impacts']['added']] == ['high']
    assert diff_programs(after, after) == {}

def test_fields_missing_from_old_snapshots_are_a_baseline() -> None:
    legacy = {key: value for key, value in normalize_program(source(max_bounty=None)).items() if key not in {'impacts', 'known_issues'}}
    assert diff_programs(legacy, normalize_program(source())) == {}

async def test_sync_records_update_linked_to_program() -> None:
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        program, _, first = await save_program(db, Client(), source())
        assert first is None
        _, _, same = await save_program(db, Client(), source())
        assert same is None
        _, _, update = await save_program(db, Client(), source(known_issues=[{'description': 'Oracle delay', 'link': 'https://x.example'}]))
        assert update.program_id == program.id and update.categories == ['known_issues']
        assert update.changes['known_issues']['added'][0]['description'] == 'Oracle delay'
        event = db.scalar(select(Event).where(Event.event_type == 'PROGRAM_UPDATED'))
        assert event.payload['update_id'] == update.id and event.payload['categories'] == ['known_issues']
        assert program_detail(program.id, db)['updates'][0]['categories'] == ['known_issues']
        assert programs(db, 0, 25, '', '', 'all')['items'][0]['latest_update']['id'] == update.id
        assert len(db.scalars(select(ProgramUpdate)).all()) == 1

def test_hackenproof_sections() -> None:
    soup = BeautifulSoup('''<div><span>Range of bounty</span><span>$0 - $20,000</span></div>
      <div class="markdown-body"><h2>IN SCOPE VULNERABILITIES: Smart Contracts</h2><ul><li>Reentrancy</li><li>Loss of funds</li></ul>
      <h2>OUT OF SCOPE VULNERABILITIES: Smart Contracts</h2><ul><li>Gas optimizations</li></ul></div>
      <section><h2>Known Issues</h2><div><p>Audit findings are known:</p><ul><li><a href="/redirect?url=https%3A%2F%2Fexample.com%2Faudit.pdf">Audit</a></li></ul></div></section>''', 'html.parser')
    assert hackenproof.max_bounty(soup) == '$20,000'
    assert [item['title'] for item in hackenproof.impacts(soup)] == ['Reentrancy', 'Loss of funds']
    assert hackenproof.known_issues(soup, 'https://hackenproof.com') == [{'description': 'Audit findings are known:', 'link': None}, {'description': 'Audit', 'link': 'https://example.com/audit.pdf'}]
