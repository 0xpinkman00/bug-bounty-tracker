from abc import ABC, abstractmethod
from dataclasses import dataclass, field

@dataclass
class SourceAsset:
    type: str
    value: str
    url: str | None = None
    in_scope: bool = True

@dataclass
class SourceProgram:
    platform: str
    platform_program_id: str
    name: str
    program_url: str
    max_bounty: str | None = None
    status: str = 'active'
    assets: list[SourceAsset] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

class BountySource(ABC):
    @abstractmethod
    async def list_programs(self) -> list[str]: ...
    @abstractmethod
    async def get_program(self, program_id: str) -> SourceProgram: ...
    async def extract_assets(self, program: SourceProgram) -> list[SourceAsset]:
        return program.assets
    async def extract_repositories(self, program: SourceProgram) -> list[str]:
        return program.repositories
