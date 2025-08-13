#!/bin/bash

# Copyright 2024 The gVisor Authors.
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

set -xeo pipefail

fail() {
  echo "FAIL: $*"
  exit 1
}

# Don't report any test cases.
echo "$@" | grep list_tests && exit 1

# When running this test inside a user namespace without host root mapped, like bazel is wont to
# do, /bin/mount appears as a setuid binary owned by (host) overflow-uid inside the container,
# and thus would rob the execing process of its exalted (sandbox) root EUID. So we make a copy if
# mount has the setuid bit set.
hostMount="$(which mount)"
if [[ -u ${hostMount} ]]; then
  cp "${hostMount}" /tmp/mount
fi

mount() {
  if [[ -x /tmp/mount ]]; then
    /tmp/mount "$@"
  else
    "${hostMount}" "$@"
  fi
}

if [[ -z "$TEST_ON_GVISOR" ]]; then
  if [[ ! -d /var/run ]]; then
    echo "SKIP: /var/run doesn't exist but it is required for the ip tool."
    exit 0
  fi
  mount -t tmpfs test /var/run
else
  mkdir -p /var/run
  mount -t tmpfs test /var/run
fi

# check_connectivity checks that a TCP connection can be established between two
# specified namespaces.
# Arguments:
# * network namespace where a server will be started
# * IP address in the server network namespace.
# * port for a test TCP connection
# * network namespace where a client will be started
# * test message that will be send from server to client
check_connectivity() {
  local srv_netns="$1"
  local srv_ip="$2"
  local port="$3"
  local clt_netns="$4"
  local test_msg="$5"

  # Create a sync pipe that will be closed when TCP_SRV creates a listen socket.
  exec {pipe}<> <(:)
  exec {pipe_r}</proc/self/fd/$pipe
  exec {pipe_w}>/proc/self/fd/$pipe
  exec {pipe}>&-
  echo "$test_msg" | ip netns exec "$srv_netns" "$TCP_SRV" "--port=$port" "--sync-fd=$pipe_w" 1>&2 &
  pid=$!
  exec {pipe_w}>&-
  cat <&$pipe_r
  exec {pipe_r}>&-
  # The server has been started.

  out=$(ip netns exec "$clt_netns" nc -nvd "$srv_ip" "$port")
  if [[ "$out" != "$test_msg" ]]; then
    fail "unexpected output '$out' (expected '$test_msg'"
  fi
  wait "$pid"
}

wait_for() {
  for _ in $(seq 50); do
    if eval "$@"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}
