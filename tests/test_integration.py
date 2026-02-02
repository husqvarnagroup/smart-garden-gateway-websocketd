import asyncio
import json

import pytest
from conftest import make_msg


@pytest.mark.asyncio
@pytest.mark.parametrize("device_service_name", ["lemonbeatd", "lwm2mserver"])
async def test_device_request(
    device_services,
    websocketd,
    ws_client,
    device_service_name,
):
    device_service = device_services[device_service_name]
    msg = make_msg(
        op="read",
        entity_path="/test",
        entity_device="foo",
        entity_service=device_service_name,
        request_id="1",
    )
    await ws_client.send(json.dumps(msg))
    await asyncio.sleep(0.1)

    requests = device_service["command"].received_requests
    assert len(requests) == 1
    assert requests[0][0]["op"] == "read"
    assert "service" not in requests[0][0]["entity"]
    assert requests[0][0]["entity"]["device"] == "foo"
    response = json.loads(await ws_client.recv())
    assert response[0]["success"] is True
    assert response[0]["request_id"] == "1"


@pytest.mark.asyncio
@pytest.mark.parametrize("device_service_name", ["lemonbeatd", "lwm2mserver"])
async def test_service_request(
    device_services,
    websocketd,
    ws_client,
    device_service_name,
):
    device_service = device_services[device_service_name]
    msg = make_msg(
        op="read",
        entity_path="devices",
        entity_service=device_service_name,
        request_id="1",
    )
    await ws_client.send(json.dumps(msg))
    await asyncio.sleep(0.1)

    requests = device_service["command"].received_requests
    assert len(requests) == 1
    assert requests[0][0]["op"] == "read"
    assert requests[0][0]["entity"]["service"] == device_service_name
    response = json.loads(await ws_client.recv())
    assert response[0]["success"] is True
    assert response[0]["request_id"] == "1"


@pytest.mark.asyncio
@pytest.mark.parametrize("device_service_name", ["lemonbeatd", "lwm2mserver"])
async def test_event(
    device_services,
    websocketd,
    ws_client,
    device_service_name,
):
    device_service = device_services[device_service_name]
    event = make_msg(op="update", entity_path="/status", payload={"state": "on"})
    await device_service["event"].publish_event(event)

    response = json.loads(await asyncio.wait_for(ws_client.recv(), timeout=2.0))
    assert response[0]["op"] == "update"
    assert response[0]["metadata"]["source"] == device_service_name
