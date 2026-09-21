from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.database import Base

def now() -> datetime:
    return datetime.now(timezone.utc)

class Program(Base):
    __tablename__ = 'programs'
    __table_args__ = (UniqueConstraint('platform', 'platform_program_id'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(80))
    platform_program_id: Mapped[str] = mapped_column(String(255))
    program_url: Mapped[str] = mapped_column(Text)
    max_bounty: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(40), default='active')
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict] = mapped_column('metadata', JSON, default=dict)
    repositories: Mapped[list['Repository']] = relationship(secondary='program_repositories', back_populates='programs')

class Repository(Base):
    __tablename__ = 'repositories'
    id: Mapped[int] = mapped_column(primary_key=True)
    github_repo_id: Mapped[int | None] = mapped_column(Integer, unique=True)
    owner: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(Text, unique=True)
    default_branch: Mapped[str | None] = mapped_column(String(255))
    last_commit_sha: Mapped[str | None] = mapped_column(String(40))
    last_release_id: Mapped[int | None] = mapped_column(Integer)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=now)
    scan_interval: Mapped[int] = mapped_column(Integer, default=3600)
    scan_failures: Mapped[int] = mapped_column(Integer, default=0)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    metadata_json: Mapped[dict] = mapped_column('metadata', JSON, default=dict)
    programs: Mapped[list[Program]] = relationship(secondary='program_repositories', back_populates='repositories')
    __table_args__ = (UniqueConstraint('owner', 'name'),)

class ProgramRepository(Base):
    __tablename__ = 'program_repositories'
    program_id: Mapped[int] = mapped_column(ForeignKey('programs.id', ondelete='CASCADE'), primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey('repositories.id', ondelete='CASCADE'), primary_key=True)
    discovered_from: Mapped[str] = mapped_column(String(40), default='manual')

class Commit(Base):
    __tablename__ = 'commits'
    __table_args__ = (UniqueConstraint('repository_id', 'sha'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey('repositories.id', ondelete='CASCADE'))
    sha: Mapped[str] = mapped_column(String(40))
    message: Mapped[str] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(255))
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class Release(Base):
    __tablename__ = 'releases'
    __table_args__ = (UniqueConstraint('repository_id', 'github_release_id'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey('repositories.id', ondelete='CASCADE'))
    github_release_id: Mapped[int] = mapped_column(Integer)
    tag: Mapped[str] = mapped_column(String(255))
    name: Mapped[str | None] = mapped_column(String(255))
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    release_url: Mapped[str] = mapped_column(Text)

class Tag(Base):
    __tablename__ = 'tags'
    __table_args__ = (UniqueConstraint('repository_id', 'name'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey('repositories.id', ondelete='CASCADE'))
    name: Mapped[str] = mapped_column(String(255))
    commit_sha: Mapped[str | None] = mapped_column(String(40))

class Event(Base):
    __tablename__ = 'events'
    __table_args__ = (UniqueConstraint('event_type', 'repository_id', 'identity'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(50))
    program_id: Mapped[int | None] = mapped_column(ForeignKey('programs.id', ondelete='SET NULL'))
    repository_id: Mapped[int | None] = mapped_column(ForeignKey('repositories.id', ondelete='CASCADE'))
    identity: Mapped[str] = mapped_column(String(255))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class Asset(Base):
    __tablename__ = 'assets'
    __table_args__ = (UniqueConstraint('program_id', 'type', 'value'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey('programs.id', ondelete='CASCADE'))
    type: Mapped[str] = mapped_column(String(50))
    value: Mapped[str] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_json: Mapped[dict] = mapped_column('metadata', JSON, default=dict)

class ProgramSnapshot(Base):
    __tablename__ = 'program_snapshots'
    __table_args__ = (UniqueConstraint('program_id', 'content_hash'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey('programs.id', ondelete='CASCADE'))
    content_hash: Mapped[str] = mapped_column(String(64))
    raw_data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ChangedFile(Base):
    __tablename__ = 'changed_files'
    __table_args__ = (UniqueConstraint('commit_id', 'filename'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    commit_id: Mapped[int] = mapped_column(ForeignKey('commits.id', ondelete='CASCADE'))
    filename: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30))
    additions: Mapped[int] = mapped_column(Integer, default=0)
    deletions: Mapped[int] = mapped_column(Integer, default=0)
    patch: Mapped[str | None] = mapped_column(Text)
    language: Mapped[str | None] = mapped_column(String(30))
    dependency_change: Mapped[bool] = mapped_column(Boolean, default=False)

class Setting(Base):
    __tablename__ = 'settings'
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)

class SourceSyncRun(Base):
    __tablename__ = 'source_sync_runs'
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(20), default='queued')
    discovered_count: Mapped[int] = mapped_column(Integer, default=0)
    program_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    next_index: Mapped[int] = mapped_column(Integer, default=0)
    processed_count: Mapped[int] = mapped_column(Integer, default=0)
    created_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
