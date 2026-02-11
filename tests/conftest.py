import asyncio
import base64
import json
import logging
import os
import ssl
from pathlib import Path
from typing import Callable, Dict, Optional

import pytest
import pytest_asyncio
import websockets

logger = logging.getLogger(__name__)


def make_msg(
    op: Optional[str] = None,
    entity_path: Optional[str] = None,
    entity_service: Optional[str] = None,
    entity_device: Optional[str] = None,
    payload: Optional[Dict] = None,
    request_id: Optional[str] = None,
    success: Optional[bool] = None,
    metadata: Optional[Dict] = None,
) -> list:
    msg = {}
    if op:
        msg["op"] = op
    if entity_path or entity_service or entity_device:
        msg["entity"] = {}
        if entity_path:
            msg["entity"]["path"] = entity_path
        if entity_service:
            msg["entity"]["service"] = entity_service
        if entity_device:
            msg["entity"]["device"] = entity_device
    if payload is not None:
        msg["payload"] = payload
    if request_id:
        msg["request_id"] = request_id
    if success is not None:
        msg["success"] = success
    if metadata:
        msg["metadata"] = metadata
    return msg


@pytest.fixture(scope="session")
def project_root() -> Path:
    return Path(__file__).parent.parent


class IPCReqService:
    def __init__(self, socket_path: Path, handler: Optional[Callable] = None):
        self.socket_path = socket_path
        self.handler = handler or self.default_handler
        self.server = None
        self.running = False
        self.received_requests = []

    async def default_handler(self, request: list) -> list:
        response = []
        for msg in request:
            resp = msg.copy()
            resp["success"] = True
            response.append(resp)
        return response

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        try:
            while self.running:
                data = await reader.readline()
                if not data:
                    break
                request_json = data.decode("utf-8").strip().replace("\\n", "\n")
                request = json.loads(request_json)
                self.received_requests.append(request)
                response = await self.handler(request)
                response_json = json.dumps(response).replace("\n", "\\n").strip() + "\n"
                writer.write(response_json.encode("utf-8"))
                await writer.drain()
        except Exception:
            logger.exception("IPC req service failed")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        self.running = True
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.unlink(missing_ok=True)

        self.server = await asyncio.start_unix_server(
            self.handle_client,
            str(self.socket_path),
        )

    async def stop(self):
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.socket_path.unlink(missing_ok=True)


class IPCSubService:
    def __init__(self, socket_path: Path):
        self.socket_path = socket_path
        self.server = None
        self.running = False
        self.clients = []

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        self.clients.append(writer)
        try:
            while self.running:
                data = await reader.read(1024)
                if not data:
                    break
        finally:
            if writer in self.clients:
                self.clients.remove(writer)
            writer.close()
            await writer.wait_closed()

    async def start(self):
        self.running = True
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.unlink(missing_ok=True)
        self.server = await asyncio.start_unix_server(
            self.handle_client,
            str(self.socket_path),
        )

    async def stop(self):
        self.running = False
        for writer in self.clients[:]:
            writer.close()
            await writer.wait_closed()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.socket_path.unlink(missing_ok=True)

    async def publish_event(self, event: list):
        event_json = json.dumps(event).replace("\n", "\\n").strip() + "\n"
        event_bytes = event_json.encode("utf-8")
        for writer in self.clients[:]:
            try:
                writer.write(event_bytes)
                await writer.drain()
            except Exception:
                if writer in self.clients:
                    self.clients.remove(writer)


async def init_ipc(service_name: str) -> Dict[str, IPCReqService | IPCSubService]:
    req = IPCReqService(Path(f"/tmp/{service_name}-command.ipc"))
    sub = IPCSubService(Path(f"/tmp/{service_name}-event.ipc"))
    await req.start()
    await sub.start()
    return {"command": req, "event": sub}


@pytest_asyncio.fixture
async def device_services():
    lemonbeatd = await init_ipc("lemonbeatd")
    lwm2mserver = await init_ipc("lwm2mserver")

    yield {"lemonbeatd": lemonbeatd, "lwm2mserver": lwm2mserver}

    await lemonbeatd["command"].stop()
    await lemonbeatd["event"].stop()
    await lwm2mserver["command"].stop()
    await lwm2mserver["event"].stop()


@pytest_asyncio.fixture
async def websocketd(project_root):
    env = os.environ.copy()
    env["RUST_LOG"] = "websocketd=debug"
    proc = await asyncio.create_subprocess_exec(
        "cargo",
        "run",
        env=env,
        cwd=project_root,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:

        async def wait_for_websocketd():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    await proc.wait()
                    pytest.fail(f"Failed to start websocketd, rc={proc.returncode}")

                logger.debug(line.decode().strip())

                if b"WebSocket server listening on" in line:
                    break

        await asyncio.wait_for(wait_for_websocketd(), timeout=120)
    except asyncio.TimeoutError:
        proc.terminate()
        await proc.wait()
        pytest.fail("Timeout waiting for websocketd to start")
    except Exception:
        logger.exception("Failed to start websocketd")
        proc.terminate()
        await proc.wait()
        raise

    yield proc
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()


@pytest_asyncio.fixture
async def ws_client():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    credentials = base64.b64encode(b"user:password-for-dev").decode()
    async with websockets.connect(
        "wss://localhost:8443",
        ssl=ssl_context,
        additional_headers={"Authorization": f"Basic {credentials}"},
    ) as ws:
        yield ws
