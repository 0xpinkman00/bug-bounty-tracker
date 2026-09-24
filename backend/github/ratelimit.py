"""Shared record of GitHub rate limiting, so every scan can stop until the limit resets."""
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.github.client import RateLimitError
from backend.models import Setting

KEY = 'github_rate_limit'

def record_rate_limit(db: Session, exc: RateLimitError) -> None:
    value = {'hit_at': datetime.now(timezone.utc).isoformat(), 'reset_at': exc.reset_at.isoformat()}
    entry = db.get(Setting, KEY)
    if entry is None:
        db.add(Setting(key=KEY, value=value))
    else:
        entry.value = value
    db.commit()

def rate_limit_status(db: Session) -> dict | None:
    """The active rate limit, or None once it has reset."""
    entry = db.get(Setting, KEY)
    if entry is None or datetime.fromisoformat(entry.value['reset_at']) <= datetime.now(timezone.utc):
        return None
    return entry.value

def rate_limit_error(db: Session) -> RateLimitError | None:
    status = rate_limit_status(db)
    return RateLimitError(datetime.fromisoformat(status['reset_at'])) if status else None
