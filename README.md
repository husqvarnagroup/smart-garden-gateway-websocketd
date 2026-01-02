# GARDENA smart Gateway WebSocket daemon

Enables controlling and monitoring GARDENA smart system devices in the
local network, without going through the cloud. A corresponding
integration for e.g. Home Assistant is yet to be developed.

## Enabling WebSocket support on the gateway

At least for now, you need shell access to your GARDENA smart Gateway.
The instructions for that can be found in the
[smart-garden-gateway-public] repository.

On the gateway, run the following commands:

```txt
touch /etc/enable-websocketd
systemctl restart firewall
systemctl start websocketd
```

[smart-garden-gateway-public]: https://github.com/husqvarnagroup/smart-garden-gateway-public#getting-access

## Development

To enable IPC forwarding, run the following commands on the gateway:

```txt
fw_setenv dev_debug_enable_ipcforward 1
systemctl start ipcforward-lemonbeatd.service
systemctl start ipcforward-lwm2mserver.service
```

Then, to forward IPC to UNIX domain sockets in `/tmp`, run:

```txt
./forward-ipc.sh GARDENA-123456
```

Run the daemon with debug output:

```txt
RUST_LOG=websocketd=debug cargo run
```
