import asyncio

import pytest

from backend.notifications.ubuntu import UbuntuNotificationProvider


@pytest.mark.asyncio
async def test_summary_notification_uses_user_session_bus(monkeypatch, tmp_path) -> None:
    (tmp_path / 'bus').touch()
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(tmp_path))
    monkeypatch.delenv('DBUS_SESSION_BUS_ADDRESS', raising=False)
    calls = []

    class Process:
        returncode = 0

        async def communicate(self):
            return b'', b''

    async def create_process(*args, **kwargs):
        calls.append((args, kwargs))
        return Process()

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', create_process)
    assert await UbuntuNotificationProvider().send_text('Scan finished', 'Two releases found')
    assert calls[0][0] == ('notify-send', 'Scan finished', 'Two releases found')
    assert calls[0][1]['env']['DBUS_SESSION_BUS_ADDRESS'] == f'unix:path={tmp_path}/bus'
