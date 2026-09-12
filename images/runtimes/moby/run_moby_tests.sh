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

#!/bin/bash
BATCH_NAME=$1
TEST_LIST=$2

set -xeo pipefail
cd /moby

# Clean up any previous runs.
git reset --hard HEAD
git clean -fd

# Mount tmpfs if needed
if [[ ! -d /var/lib/docker ]]; then
  mkdir -p /var/lib/docker
fi
current_fs=$(stat -f -c %T /var/lib/docker 2>/dev/null || echo "none")
if [[ "${current_fs}" != "tmpfs" ]]; then
  mount -t tmpfs -o size=2G tmpfs /var/lib/docker
fi

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding || true
echo 1 > /proc/sys/net/ipv6/conf/default/forwarding || true

# Build dockerd and docker-proxy
if [[ ! -f /usr/local/bin/dockerd ]]; then
  go build -o /usr/local/bin/dockerd ./cmd/dockerd
  go build -o /usr/local/bin/docker-proxy ./cmd/docker-proxy
fi

# Start dockerd
dockerd --ipv6 --userland-proxy=false --feature containerd-snapshotter=false -D > /tmp/dockerd.log 2>&1 &
DOCKERD_PID=$!

# Wait for dockerd
for i in {1..30}; do
  if ! kill -0 $DOCKERD_PID 2>/dev/null; then
    echo "dockerd died early! Logs:"
    cat /tmp/dockerd.log
    exit 1
  fi
  if curl -s --unix-socket /var/run/docker.sock http://localhost/_ping >/dev/null; then
    echo "dockerd is healthy!"
    break
  fi
  sleep 1
done

if [[ $i -eq 30 ]]; then
  echo "Timeout waiting for dockerd! Logs:"
  cat /tmp/dockerd.log
  exit 1
fi

# Load required images for tests.
echo "Loading required images for tests..."
echo "Loading hello-world:latest..."
docker load -i /docker-images/hello-world.tar
echo "Loading busybox..."
docker load -i /docker-images/busybox.tar
docker tag busybox:1.36 busybox:latest || true

# Set up artifacts directory
ARTIFACTS_DIR="/tmp/moby-integration-dest"
if [[ -d /proctor-artifacts ]]; then
  ARTIFACTS_DIR="/proctor-artifacts"
fi
mkdir -p "$ARTIFACTS_DIR"

# Run tests
echo "Running tests with DOCKER_HOST=unix:///var/run/docker.sock"
EXIT_CODE=0
for test in $TEST_LIST; do
  echo "Running test $test"
  TEST_ARTIFACTS_DIR=$ARTIFACTS_DIR/$test
  mkdir -p "$TEST_ARTIFACTS_DIR"
  actual_test=${test##*/}
  TEST_TMPDIR=/tmp/t-$actual_test
  mkdir -p "$TEST_TMPDIR"

  # Create Dockerfile required by TestMain (inside loop to be safe against cleanup)
  mkdir -p /moby/integration
  cp /moby/Dockerfile /moby/integration/Dockerfile || touch /moby/integration/Dockerfile

  # Run test and capture output in test.log
  TMPDIR="$TEST_TMPDIR" DOCKER_HOST="unix:///var/run/docker.sock" DOCKER_INTEGRATION_DAEMON_DEST="$TEST_ARTIFACTS_DIR" go test -v ./integration/network -run "^$actual_test$" 2>&1 | tee "$TEST_ARTIFACTS_DIR"/test.log || EXIT_CODE=1

  echo "Collecting logs for $test"
  # Copy isolated temp files
  cp -a "$TEST_TMPDIR"/. "$TEST_ARTIFACTS_DIR"/ || true
  # Copy dockerd logs
  find /tmp -name "dockerd.*" -exec cp {} "$TEST_ARTIFACTS_DIR"/ \; || true
  find /var/log -name "*.log" -exec cp {} "$TEST_ARTIFACTS_DIR"/ \; || true

  echo "Saved logs for $test to $TEST_ARTIFACTS_DIR"
done

# Copy outer dockerd logs to artifacts too
cp /tmp/dockerd.log "$ARTIFACTS_DIR"/outer-dockerd-"${BATCH_NAME}".log || true

# Cleanup
kill $DOCKERD_PID || true
wait $DOCKERD_PID || true
umount /var/lib/docker || true

exit $EXIT_CODE
