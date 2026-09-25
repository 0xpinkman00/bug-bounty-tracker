from datetime import date
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from backend.database import Base
from backend.main import (VulnerabilityInput, create_vulnerability, delete_vulnerability, program_detail,
                          update_vulnerability, vulnerabilities, vulnerability_detail)
from backend.models import Program, ProgramSnapshot, Repository

@pytest.fixture
def db():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Program(id=1, name='Acme', platform='immunefi', platform_program_id='acme', program_url='https://immunefi.com/acme'))
        session.add(Repository(id=1, owner='acme', name='core', url='https://github.com/acme/core'))
        session.commit()
        yield session

def report(**changes) -> VulnerabilityInput:
    values = dict(title=' Reentrancy in withdraw ', severity='critical', report_type='Smart Contract', target=' https://github.com/acme/core ',
                  impacts=['Direct theft of any user funds', ' ', 'Direct theft of any user funds'], brief='Funds can be drained.',
                  proof_of_concept='```solidity\nattack();\n```', fix_url='', reported_at=date(2026, 9, 1), program_id=1, repository_id=1)
    return VulnerabilityInput(**{**values, **changes})

def test_report_lifecycle_and_filters(db) -> None:
    created = create_vulnerability(report(), db)
    assert (created['title'], created['target'], created['fix_url'], created['reported_at']) == ('Reentrancy in withdraw', 'https://github.com/acme/core', None, '2026-09-01')
    assert created['impacts'] == ['Direct theft of any user funds']
    assert (created['program_name'], created['repository_name']) == ('Acme', 'acme/core')
    create_vulnerability(report(title='Rounding', severity='low', repository_id=None), db)
    assert vulnerabilities(db, 0, 25, '', 'critical', None, None)['total'] == 1
    assert [item['title'] for item in vulnerabilities(db, 0, 25, '', '', None, 1)['items']] == ['Reentrancy in withdraw']
    updated = update_vulnerability(created['id'], report(severity='high', fix_url='https://github.com/acme/core/pull/7'), db)
    assert (updated['severity'], updated['fix_url']) == ('high', 'https://github.com/acme/core/pull/7')
    delete_vulnerability(created['id'], db)
    with pytest.raises(HTTPException):
        vulnerability_detail(created['id'], db)

def test_rejects_unknown_links_and_blank_title(db) -> None:
    for bad in (report(program_id=99), report(repository_id=99), report(title='  ')):
        with pytest.raises(HTTPException) as error:
            create_vulnerability(bad, db)
        assert error.value.status_code == 422

def test_program_detail_offers_current_impacts(db) -> None:
    db.add(ProgramSnapshot(program_id=1, content_hash='x', raw_data={'impacts': [{'type': 'smart_contract', 'severity': 'critical', 'title': 'Direct theft of any user funds'}]}))
    db.commit()
    assert program_detail(1, db)['impacts'][0]['title'] == 'Direct theft of any user funds'

def test_tags_and_extra_sections(db) -> None:
    from backend.main import vulnerability_tags
    near = create_vulnerability(report(tags=['NEAR', ' NEAR ', ''], extra_sections=[{'title': 'TL;DR', 'body': 'Short.', 'placement': 'before'}, {'title': 'Empty', 'body': ' '}]), db)
    create_vulnerability(report(title='Sei bug', tags=['Sei']), db)
    assert near['tags'] == ['NEAR']
    assert near['extra_sections'] == [{'title': 'TL;DR', 'body': 'Short.', 'placement': 'before'}]
    assert vulnerability_tags(db) == ['NEAR', 'Sei']
    assert [item['title'] for item in vulnerabilities(db, 0, 25, '', '', None, None, 'Sei')['items']] == ['Sei bug']

def test_neighbors_follow_list_order_and_filters(db) -> None:
    from backend.main import vulnerability_neighbors
    old = create_vulnerability(report(title='Old', tags=['Sei'], reported_at=date(2026, 8, 1)), db)
    mid = create_vulnerability(report(title='Mid', tags=['NEAR'], reported_at=date(2026, 8, 15)), db)
    new = create_vulnerability(report(title='New', tags=['Sei'], reported_at=date(2026, 9, 1)), db)
    assert vulnerability_neighbors(mid['id'], db) == {'previous': new['id'], 'next': old['id'], 'position': 2, 'total': 3}
    assert vulnerability_neighbors(new['id'], db, tag='Sei') == {'previous': None, 'next': old['id'], 'position': 1, 'total': 2}
    assert vulnerability_neighbors(mid['id'], db, tag='Sei') == {'previous': None, 'next': None, 'position': None, 'total': 2}
