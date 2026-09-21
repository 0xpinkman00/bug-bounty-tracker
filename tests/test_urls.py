import pytest
from backend.github.client import normalize_github_url

@pytest.mark.parametrize('url', [
    'https://github.com/example/contracts',
    'https://github.com/example/contracts/',
    'https://github.com/example/contracts/tree/main',
    'https://github.com/example/contracts/blob/main/src/Vault.sol',
])
def test_normalize(url: str) -> None:
    assert normalize_github_url(url) == ('example', 'contracts')

@pytest.mark.parametrize('url', ['https://evil.com/example/contracts', 'https://github.com/example', 'http://github.com/a/b'])
def test_reject(url: str) -> None:
    with pytest.raises(ValueError):
        normalize_github_url(url)
