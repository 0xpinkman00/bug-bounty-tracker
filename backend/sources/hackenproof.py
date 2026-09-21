import httpx
from bs4 import BeautifulSoup
from backend.sources.base import BountySource, SourceProgram
from backend.sources.common import github_links, scope_assets

class HackenProofSource(BountySource):
    base = 'https://hackenproof.com'
    def __init__(self) -> None:
        self.client = httpx.AsyncClient(timeout=30, follow_redirects=True)
    async def close(self) -> None:
        await self.client.aclose()
    async def list_programs(self) -> list[str]:
        found: set[str] = set()
        for page in range(1, 101):
            response = await self.client.get(f'{self.base}/programs', params={'page': page})
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            current = {a['href'].split('/')[2] for a in soup.select('a[href^="/programs/"]') if len(a['href'].split('/')) >= 3 and a['href'].split('/')[2]}
            if not current or current <= found:
                break
            found.update(current)
        return sorted(found)
    async def get_program(self, program_id: str) -> SourceProgram:
        url = f'{self.base}/programs/{program_id}'
        response = await self.client.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.find('h1')
        assets = scope_assets(soup, 'table tbody tr')
        return SourceProgram('hackenproof', program_id, title.get_text(' ', strip=True) if title else program_id, url, assets=assets, repositories=github_links(response.text))
