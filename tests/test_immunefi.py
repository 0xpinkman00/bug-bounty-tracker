import httpx
import pytest
from backend.sources.immunefi import ImmunefiSource

@pytest.mark.asyncio
async def test_catalog_normalization() -> None:
    payload = [{'slug':'example','project':'Example','maxBounty':25000,'isPaused':False,'assets':[{'type':'smart_contract','url':'https://etherscan.io/address/abc'},{'type':'websites_and_applications','url':'https://github.com/org/repo/tree/main'}], 'githubUrl':'https://github.com/another/project','impacts':[{'id':1,'type':'smart_contract','severity':'critical','title':' Theft of funds '}],'knownIssues':[{'id':2,'description':'Rounding','link':'https://x.example'}]},
               {'slug':'example-attackathon','project':'Attackathon | Example','endDate':'2026-01-01T00:00:00.000Z','features':['Attackathon']}]
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path == '/public-api/bounties.json'
        return httpx.Response(200, json=payload)
    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    source = ImmunefiSource(client)
    try:
        assert await source.list_programs() == ['example']
        program = await source.get_program('example')
        assert program.name == 'Example' and program.max_bounty == '$25,000'
        assert [asset.type for asset in program.assets] == ['smart_contract','github_repository']
        assert len(program.repositories) == 2
        assert program.impacts == [{'type':'smart_contract','severity':'critical','title':'Theft of funds'}]
        assert program.known_issues == [{'description':'Rounding','link':'https://x.example'}]
    finally:
        await source.close()
