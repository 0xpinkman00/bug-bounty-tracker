from backend.sources.base import SourceAsset, SourceProgram
from backend.services.discovery import normalize_program, compare_snapshots
from backend.github.scanner import classify_file

def test_program_normalization() -> None:
    item = SourceProgram('Immunefi', ' test ', ' Example ', 'https://example.com', assets=[SourceAsset('website',' https://example.com ')])
    result = normalize_program(item)
    assert result['platform'] == 'immunefi'
    assert result['name'] == 'Example'
    assert result['assets'][0]['value'] == 'https://example.com'

def test_snapshot_and_scope_change() -> None:
    before = {'assets': [{'type': 'website', 'value': 'old', 'in_scope': True}]}
    after = {'assets': [{'type': 'website', 'value': 'new', 'in_scope': True}]}
    assert compare_snapshots(before, after) == ({('website','new')}, {('website','old')})
    assert compare_snapshots(after, after) == (set(), set())

def test_file_classification() -> None:
    assert classify_file('src/Vault.sol') == ('Solidity', False)
    assert classify_file('Cargo.lock') == (None, True)
