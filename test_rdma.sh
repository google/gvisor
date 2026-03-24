#!/usr/bin/env bash
set -euo pipefail

RUNTIME="runsc-rdma"
BIN="/usr/local/bin/${RUNTIME}"
LOGDIR="/tmp/${RUNTIME}/logs"
DEV="/dev/infiniband/uverbs0"

# Build
cd "$(dirname "$0")"
sudo make copy TARGETS=runsc DESTINATION=/tmp 2>&1 | tail -3

# Deploy
sudo pkill -f "$RUNTIME" 2>/dev/null || true
sleep 1
sudo rm -f "$BIN"
sudo cp /tmp/runsc "$BIN"
sudo chmod +x "$BIN"

# Configure daemon.json
sudo python3 -c "
import json, os
p = '/etc/docker/daemon.json'
d = json.load(open(p)) if os.path.exists(p) else {}
d.setdefault('runtimes', {})['${RUNTIME}'] = {
    'path': '${BIN}',
    'runtimeArgs': ['--debug', '--debug-log=${LOGDIR}/', '--rdmaproxy', '--rdma-expected-ipoib=-1']
}
json.dump(d, open(p,'w'), indent=2)
"
sudo systemctl restart docker
sleep 2
sudo rm -rf "$LOGDIR" && sudo mkdir -p "$LOGDIR"

# Test
echo "=== Test 1: sysfs + devnodes ==="
sudo docker run --runtime="$RUNTIME" --rm --device="$DEV" ubuntu:22.04 bash -c '
ls /sys/class/infiniband_verbs/
ls /sys/class/infiniband/
ls /dev/infiniband/
cat /sys/class/infiniband_verbs/uverbs*/dev
'

echo "=== Test 2: ibv_devinfo ==="
sudo docker run --runtime="$RUNTIME" --rm --device="$DEV" ubuntu:22.04 bash -c '
apt-get update -qq >/dev/null 2>&1
apt-get install -yqq ibverbs-utils >/dev/null 2>&1
ibv_devinfo 2>&1; echo "EXIT=$?"
'

echo "=== Sentry logs ==="
BOOTLOG=$(ls -t "$LOGDIR"/ 2>/dev/null | grep boot | head -1)
[ -n "$BOOTLOG" ] && grep -iE 'rdma|uverbs|infiniband' "$LOGDIR/$BOOTLOG" | tail -40
