#!/bin/sh

# To enable IPC forwarding, run the following commands on the gateway:
#
# fw_setenv dev_debug_enable_ipcforward 1
# systemctl start ipcforward-lemonbeatd.service
# systemctl start ipcforward-lwm2mserver.service

if [ $# -lt 1 ]; then
    echo "No host provided, usage: $0 GARDENA-123456" >&2
    exit 1
fi
host=$1
socat UNIX-LISTEN:/tmp/lemonbeatd-command.ipc,fork,reuseaddr,unlink-early TCP:$host:28153 &
socat UNIX-LISTEN:/tmp/lemonbeatd-event.ipc,fork,reuseaddr,unlink-early TCP:$host:28152 &
socat UNIX-LISTEN:/tmp/lwm2mserver-command.ipc,fork,reuseaddr,unlink-early TCP:$host:28151 &
socat UNIX-LISTEN:/tmp/lwm2mserver-event.ipc,fork,reuseaddr,unlink-early TCP:$host:28150 &
