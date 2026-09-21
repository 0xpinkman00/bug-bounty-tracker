import re
from urllib.parse import urlparse
import httpx
from backend.config import settings

OWNER_REPO = re.compile(r'^[A-Za-z0-9_.-]+$')

def normalize_github_url(value: str) -> tuple[str, str]:
    parsed = urlparse(value.strip())
    if parsed.scheme != 'https' or parsed.hostname not in {'github.com', 'www.github.com'} or parsed.username or parsed.password or parsed.port:
        raise ValueError('Enter an https://github.com/owner/repository URL')
    parts = [part for part in parsed.path.split('/') if part]
    if len(parts) < 2 or not all(OWNER_REPO.fullmatch(part) for part in parts[:2]):
        raise ValueError('Invalid GitHub repository URL')
    owner, name = parts[:2]
    name = name.removesuffix('.git')
    if not name or name in {'.', '..'} or owner in {'.', '..'}:
        raise ValueError('Invalid GitHub repository URL')
    return owner, name

class GitHubError(Exception):
    pass

class GitHubClient:
    def __init__(self) -> None:
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if settings.github_token:
            headers['Authorization'] = f'Bearer {settings.github_token}'
        self.client = httpx.AsyncClient(base_url='https://api.github.com', headers=headers, timeout=20)

    async def close(self) -> None:
        await self.client.aclose()

    async def get(self, path: str, params: dict | None = None) -> dict | list:
        response = await self.client.get(path, params=params)
        if response.status_code == 403 and response.headers.get('X-RateLimit-Remaining') == '0':
            raise GitHubError('GitHub rate limit reached')
        if response.status_code == 404:
            raise GitHubError('Repository or resource not found')
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise GitHubError(f'GitHub API returned {response.status_code}') from exc
        return response.json()
