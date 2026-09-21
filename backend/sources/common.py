import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from backend.sources.base import SourceAsset

GITHUB_LINK = re.compile(r'https://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s"<>]*)?')

def github_links(html: str) -> list[str]:
    return sorted(set(GITHUB_LINK.findall(html)))

def scope_assets(soup: BeautifulSoup, selector: str) -> list[SourceAsset]:
    assets: dict[tuple[str, str], SourceAsset] = {}
    for row in soup.select(selector):
        text = row.get_text(' ', strip=True)
        for link in row.find_all('a', href=True):
            url = link['href']
            if url.startswith('https://'):
                hostname = urlparse(url).hostname
                kind = 'github_repository' if hostname == 'github.com' else 'smart_contract' if hostname in {'etherscan.io', 'bscscan.com', 'polygonscan.com', 'arbiscan.io'} else 'website'
                assets[(kind, url)] = SourceAsset(kind, url, url)
        if not row.find('a', href=True) and text and len(text) < 300:
            assets[('other', text)] = SourceAsset('other', text)
    return list(assets.values())
