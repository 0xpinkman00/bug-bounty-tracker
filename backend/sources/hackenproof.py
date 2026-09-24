import re
import httpx
from bs4 import BeautifulSoup
from backend.sources.base import BountySource, SourceProgram
from backend.sources.common import github_links, resolve_link, scope_assets, section_blocks

AMOUNT = re.compile(r'\$\s?[\d,]+(?:\.\d+)?')

def max_bounty(soup: BeautifulSoup) -> str | None:
    label = soup.find(string=re.compile(r'Range of bounty', re.I))
    row = label.find_parent('div') if label else None
    amounts = AMOUNT.findall(row.get_text(' ', strip=True)) if row else []
    return amounts[-1].replace(' ', '') if amounts else None

def impacts(soup: BeautifulSoup) -> list[dict]:
    found = []
    for heading in soup.find_all(['h2', 'h3']):
        title = heading.get_text(' ', strip=True)
        if title.upper().startswith('IN SCOPE VULNERABILITIES'):
            kind = title.split(':', 1)[1].strip() if ':' in title else None
            found += [{'type': kind, 'severity': None, 'title': item.get_text(' ', strip=True)}
                      for item in section_blocks(heading) if item.name == 'li' and item.get_text(strip=True)]
    return found

def known_issues(soup: BeautifulSoup, base: str) -> list[dict]:
    heading = next((h for h in soup.find_all(['h2', 'h3']) if h.get_text(' ', strip=True).lower() == 'known issues'), None)
    if heading is None:
        return []
    issues = []
    for block in section_blocks(heading):
        text, link = block.get_text(' ', strip=True), block.find('a', href=True)
        if text:
            issues.append({'description': text, 'link': resolve_link(link['href'], base) if link else None})
    return issues

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
        return SourceProgram('hackenproof', program_id, title.get_text(' ', strip=True) if title else program_id, url,
                             max_bounty=max_bounty(soup), assets=assets, repositories=github_links(response.text),
                             impacts=impacts(soup), known_issues=known_issues(soup, self.base))
