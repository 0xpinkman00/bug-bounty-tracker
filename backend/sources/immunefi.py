import httpx
from backend.sources.base import BountySource, SourceAsset, SourceProgram
from backend.sources.common import github_links

class ImmunefiSource(BountySource):
    catalog_url = 'https://immunefi.com/public-api/bounties.json'

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self.client = client or httpx.AsyncClient(timeout=120, follow_redirects=True)
        self._programs: dict[str, dict] | None = None

    async def close(self) -> None:
        await self.client.aclose()

    async def _catalog(self) -> dict[str, dict]:
        if self._programs is None:
            response = await self.client.get(self.catalog_url)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, list):
                raise ValueError('Immunefi catalog format changed')
            self._programs = {item['slug']: item for item in data if isinstance(item, dict) and item.get('slug')}
        return self._programs

    async def list_programs(self) -> list[str]:
        return sorted(await self._catalog())

    async def get_program(self, program_id: str) -> SourceProgram:
        item = (await self._catalog())[program_id]
        assets: list[SourceAsset] = []
        repositories: set[str] = set(github_links(str(item.get('githubUrl') or '')))
        for asset in item.get('assets') or []:
            url = asset.get('url') or None
            value = url or asset.get('description') or asset.get('id')
            if not value:
                continue
            kind = 'smart_contract' if asset.get('type') == 'smart_contract' else 'github_repository' if url and 'github.com/' in url else 'website'
            assets.append(SourceAsset(type=kind, value=str(value), url=url))
            repositories.update(github_links(str(url or '')))
            repositories.update(github_links(str(asset.get('description') or '')))
        maximum = item.get('maxBounty')
        return SourceProgram(
            platform='immunefi',
            platform_program_id=program_id,
            name=item.get('project') or program_id,
            program_url=f'https://immunefi.com/bug-bounty/{program_id}/scope/',
            max_bounty=f'${maximum:,}' if isinstance(maximum, (int, float)) else None,
            status='paused' if item.get('isPaused') else 'active',
            assets=assets,
            repositories=sorted(repositories),
            metadata={'updated_date': item.get('updatedDate')},
        )
