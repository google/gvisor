#!/bin/bash

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Bring up the X11 <-> RDP bridge and the MCP server.
set -eu

: "${RDP_HOST:=gnome}"
: "${RDP_PORT:=3389}"
: "${RDP_USER:=gnome}"
: "${RDP_PASSWORD:=gnome}"
: "${SCREEN_WIDTH:=1280}"
: "${SCREEN_HEIGHT:=800}"
: "${DISPLAY:=:1}"
export DISPLAY SCREEN_WIDTH SCREEN_HEIGHT

Xvfb "$DISPLAY" -screen 0 "${SCREEN_WIDTH}x${SCREEN_HEIGHT}x24" -nolisten tcp +extension RANDR &
for _ in $(seq 50); do xdpyinfo -display "$DISPLAY" >/dev/null 2>&1 && break; sleep 0.2; done
xdpyinfo -display "$DISPLAY" >/dev/null

xdotool mousemove $((SCREEN_WIDTH / 2)) $((SCREEN_HEIGHT / 2)) || true

rdp_loop() {
    while true; do
        xfreerdp3 \
            "/v:${RDP_HOST}:${RDP_PORT}" \
            "/u:${RDP_USER}" "/p:${RDP_PASSWORD}" \
            /cert:ignore \
            "/size:${SCREEN_WIDTH}x${SCREEN_HEIGHT}" \
            -grab-keyboard +auto-reconnect \
            /log-level:WARN || true
        echo "freerdp exited, reconnecting in 3s" >&2
        sleep 3
    done
}
rdp_loop &

exec python3 /opt/desktop-mcp/desktop_mcp.py
