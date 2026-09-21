from abc import ABC, abstractmethod
from backend.models import Event

class NotificationProvider(ABC):
    @abstractmethod
    async def send(self, event: Event) -> None:
        pass
