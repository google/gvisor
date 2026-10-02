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

set -xeo pipefail
source "$(dirname "$0")/rtnetlink_test.sh"
TCP_SRV="$(dirname "$0")/tcp_serv"
if [[ ! -f "$TCP_SRV" ]]; then
  TCP_SRV="$(dirname "$0")/tcp_serv_/tcp_serv"
fi

# The link-local addresses that the kernel derives from the MAC addresses
# below, in the default EUI-64 address generation mode.
VETH0_LL="fe80::ff:fe00:1"
VETH1_LL="fe80::ff:fe00:2"

# link_local_ready checks that an interface has the given IPv6 link-local
# address and that duplicate address detection has completed on it.
# Arguments:
# * network namespace of the interface
# * interface name
# * IPv6 link-local address
link_local_ready() {
  local out
  out=$(ip netns exec "$1" ip -6 addr show dev "$2")
  grep -q "inet6 $3/64" <<< "$out" && ! grep -q tentative <<< "$out"
}

ip netns attach rootns "$$"
ip netns add test1
# tcp_serv accepts IPv6 connections only if it can bind ::1, which needs the
# loopback interface up.
ip netns exec test1 ip link set up dev lo
ip link add veth0 address 02:00:00:00:00:01 type veth \
  peer name veth1 address 02:00:00:00:00:02 netns test1
ip addr add 192.168.12.1/24 dev veth0
ip netns exec test1 ip addr add 192.168.12.2/24 dev veth1

# Bring both ends down, then up. Coming up auto-configures their link-local
# addresses.
ip link set down dev veth0
ip netns exec test1 ip link set down dev veth1
ip link set up dev veth0
ip netns exec test1 ip link set up dev veth1
if ! wait_for link_local_ready rootns veth0 "$VETH0_LL"; then
  fail "veth0 has no link-local address after coming up"
fi
if ! wait_for link_local_ready test1 veth1 "$VETH1_LL"; then
  fail "veth1 has no link-local address after coming up"
fi
check_connectivity test1 192.168.12.2 8800 rootns "IPv4 after up"
check_connectivity test1 "$VETH1_LL%veth0" 8801 rootns "IPv6 after up"

# Going down flushes the IPv6 addresses of veth0, the link-local one included.
ip link set down dev veth0
if ip -6 addr show dev veth0 | grep -q "inet6 fe80::"; then
  fail "veth0 kept its link-local address while down"
fi

# Coming back up auto-configures the link-local address again, and veth0
# carries IPv4 and IPv6 traffic as before.
ip link set up dev veth0
if ! wait_for link_local_ready rootns veth0 "$VETH0_LL"; then
  fail "veth0 has no link-local address after coming back up"
fi
if ! wait_for link_local_ready test1 veth1 "$VETH1_LL"; then
  fail "veth1 lost its link-local address"
fi
check_connectivity test1 192.168.12.2 8802 rootns "IPv4 after down/up"
check_connectivity test1 "$VETH1_LL%veth0" 8803 rootns "IPv6 after down/up"

ip netns del test1
if ! wait_for ! ip link show veth0 2>/dev/null; then
  fail "veth0 hasn't been destroyed"
fi
