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
source "$(dirname "$0")/rtnetlink_test.sh"
TCP_SRV="$(dirname "$0")/tcp_serv"
if [[ ! -f "$TCP_SRV" ]]; then
  TCP_SRV="$(dirname "$0")/tcp_serv_/tcp_serv"
fi

ip netns attach rootns "$$"
ip link add br0 type bridge
ip netns add test0
ip netns add test1

ip link add hveth0 type veth peer name veth0 netns test0
ip link add hveth1 type veth peer name veth1 netns test1
ip link set up dev hveth0
ip link set up dev hveth1

if ip link set br0 master br0; then
  exit 1
fi

ip link set hveth0 master br0
ip link set hveth1 master br0

ip addr add 192.168.0.3/24 dev br0
ip link set up dev br0
ip netns exec test0 ip link set up dev veth0
ip netns exec test1 ip link set up dev veth1
ip netns exec test0 ip addr add 192.168.0.1/24 dev veth0
ip netns exec test1 ip addr add 192.168.0.2/24 dev veth1

check_connectivity test1 192.168.0.2 8800 test0 "ping from test0"
check_connectivity test1 192.168.0.2 8801 rootns "ping from rootns"

# Destroy namespaces and the bridge.
ip netns del test0
ip link del br0
ip netns del test1
if ! wait_for ! ip link show hveth0 2>/dev/null; then
  fail "hveth0 hasn't been destroyed"
fi
if ! wait_for ! ip link show hveth1 2>/dev/null; then
  fail "hveth1 hasn't been destroyed"
fi
if ! wait_for ! ip link show br0 2>/dev/null; then
  fail "br0 hasn't been destroyed"
fi
