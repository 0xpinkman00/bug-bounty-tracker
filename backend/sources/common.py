import re
from urllib.parse import parse_qs, urljoin, urlparse
from bs4 import BeautifulSoup, Tag
from backend.sources.base import SourceAsset

GITHUB_LINK = re.compile(r'https://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s"<>]*)?')

def github_links(html: str) -> list[str]:
    return sorted(set(GITHUB_LINK.findall(html)))

def section_blocks(heading: Tag) -> list[Tag]:
    """Paragraphs and list items between a heading and the next heading of the same level."""
    blocks = []
    for sibling in heading.find_next_siblings():
        if sibling.name == heading.name:
            break
        blocks.extend([sibling] if sibling.name in {'p', 'li'} else sibling.find_all(['p', 'li']))
    return [block for block in blocks if not block.find(['p', 'li'])]

def resolve_link(url: str, base: str) -> str:
    """Absolute URL, unwrapping a site's /redirect?url= wrapper."""
    parsed = urlparse(urljoin(base, url))
    target = parse_qs(parsed.query).get('url') if parsed.path == '/redirect' else None
    return target[0] if target else parsed.geturl()

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
