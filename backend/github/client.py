import re
from datetime import datetime, timedelta, timezone
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

class RateLimitError(GitHubError):
    def __init__(self, reset_at: datetime) -> None:
        self.reset_at = reset_at
        minutes = max(1, round((reset_at - datetime.now(timezone.utc)).total_seconds() / 60))
        super().__init__(f'GitHub rate limit reached; resets in {minutes} min')

def rate_limit_reset(response: httpx.Response) -> datetime | None:
    """When a rate-limited response may be retried, or None if the response is not rate limited."""
    if response.status_code not in (403, 429):
        return None
    headers = response.headers
    if headers.get('X-RateLimit-Remaining') != '0' and 'rate limit' not in response.text.lower():
        return None
    if headers.get('Retry-After', '').isdigit():
        return datetime.now(timezone.utc) + timedelta(seconds=int(headers['Retry-After']))
    if headers.get('X-RateLimit-Reset', '').isdigit():
        return datetime.fromtimestamp(int(headers['X-RateLimit-Reset']), timezone.utc)
    return datetime.now(timezone.utc) + timedelta(minutes=1)

class GitHubClient:
    def __init__(self) -> None:
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if settings.github_token:
            headers['Authorization'] = f'Bearer {settings.github_token}'
        # Renamed repositories answer 301 with the new location; without this they look unreachable.
        self.client = httpx.AsyncClient(base_url='https://api.github.com', headers=headers, timeout=20, follow_redirects=True)

    async def close(self) -> None:
        await self.client.aclose()

    async def get(self, path: str, params: dict | None = None) -> dict | list:
        response = await self.client.get(path, params=params)
        if reset_at := rate_limit_reset(response):
            raise RateLimitError(reset_at)
        if response.status_code == 404:
            raise GitHubError('Repository or resource not found')
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise GitHubError(f'GitHub API returned {response.status_code}') from exc
        return response.json()
