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

# Checks what "ip link set dev DEV up/down" does to the link flags, addresses,
# routes and traffic.

set -xeo pipefail
source "$(dirname "$0")/rtnetlink_test.sh"
TCP_SRV="$(dirname "$0")/tcp_serv"
if [[ ! -f "$TCP_SRV" ]]; then
  TCP_SRV="$(dirname "$0")/tcp_serv_/tcp_serv"
fi

# link_is_up and link_is_down check the IFF_UP flag and the operational state
# of a link.
# Arguments:
# * network namespace
# * link name
link_is_up() {
  local out
  out="$(ip netns exec "$1" ip -o link show dev "$2")"
  [[ "$out" =~ [\<,]UP[,\>] ]] || fail "$2 is not up: $out"
}

# probe_tcp prints "reachable" if a TCP connection attempt gets an answer
# (connected or refused), "unreachable" if it fails at once, and "timeout" if
# no answer comes.
# Arguments:
# * network namespace
# * IP address
probe_tcp() {
  local out rc=0
  out="$(timeout 3 ip netns exec "$1" bash -c "echo > /dev/tcp/$2/9" 2>&1)" || rc=$?
  if [[ $rc -eq 0 || "$out" =~ "Connection refused" ]]; then
    echo reachable
  elif [[ $rc -eq 124 ]]; then
    echo timeout
  elif [[ "$out" =~ "Network is unreachable" ]]; then
    echo unreachable
  else
    echo "unknown: rc=$rc $out"
  fi
}

link_is_down() {
  local out
  out="$(ip netns exec "$1" ip -o link show dev "$2")"
  [[ ! "$out" =~ [\<,]UP[,\>] ]] || fail "$2 is not down: $out"
  [[ "$out" =~ "state DOWN" ]] || fail "$2 is not in state DOWN: $out"
}

ip netns add test0
ip netns add test1
N0="ip netns exec test0"
N1="ip netns exec test1"
$N0 ip link set lo up
$N1 ip link set lo up

ip link add veth0 netns test0 type veth peer name veth1 netns test1
$N0 ip link set veth0 up
$N1 ip link set veth1 up
link_is_up test0 veth0
# Setting the same state again is not an error.
$N0 ip link set veth0 up
$N0 ip addr add 10.1.0.1/24 dev veth0
$N1 ip addr add 10.1.0.2/24 dev veth1
$N0 ip addr add 2001:db8:1::1/64 dev veth0 nodad
$N0 ip route add 10.2.0.0/24 via 10.1.0.2
$N0 ip -6 route add 2001:db8:3::/64 dev veth0
check_connectivity test1 10.1.0.2 8800 test0 "before down"

$N0 ip -o monitor link > /tmp/link_updown_monitor.txt 2>&1 &
monitor_pid=$!
sleep 1

# Bring the link down.
$N0 ip link set veth0 down
link_is_down test0 veth0
if ! wait_for grep -q "'veth0.*state DOWN'" /tmp/link_updown_monitor.txt; then
  cat /tmp/link_updown_monitor.txt
  fail "no RTM_NEWLINK notification for the link going down"
fi
kill "$monitor_pid"
# IPv4 addresses stay, IPv6 addresses are removed.
$N0 ip -4 addr show dev veth0 | grep -q "10.1.0.1/24" || fail "IPv4 address removed"
if $N0 ip -6 addr show dev veth0 | grep -q "2001:db8:1::1"; then
  fail "IPv6 address not removed"
fi
# All routes through the link are removed.
[[ -z "$($N0 ip -4 route show dev veth0)" ]] || fail "IPv4 routes not removed"
[[ -z "$($N0 ip -6 route show dev veth0)" ]] || fail "IPv6 routes not removed"
if $N0 ip route get 10.1.0.2; then
  fail "route to 10.1.0.2 found"
fi
if out="$($N0 bash -c 'echo > /dev/tcp/10.1.0.2/8801' 2>&1)"; then
  fail "connected through a link that is down"
fi
[[ "$out" =~ "Network is unreachable" ]] || fail "unexpected error: $out"
# Routes through a link that is down are rejected.
if $N0 ip route add 10.4.0.0/24 dev veth0; then
  fail "added a route through a link that is down"
fi
if $N0 ip route add 10.5.0.0/24 via 10.1.0.2; then
  fail "added a route through a gateway behind a link that is down"
fi
# Addresses can be added, but their prefix routes wait for the link.
$N0 ip addr add 10.9.0.1/24 dev veth0
$N0 ip -6 addr add 2001:db8:9::1/64 dev veth0 nodad
[[ -z "$($N0 ip -4 route show dev veth0)" ]] || fail "IPv4 prefix route added while down"
[[ -z "$($N0 ip -6 route show dev veth0)" ]] || fail "IPv6 prefix route added while down"

# Bring the link up.
$N0 ip link set veth0 up
link_is_up test0 veth0
# The prefix routes of the addresses come back. Other routes do not.
$N0 ip -4 route show dev veth0 | grep -q "^10.1.0.0/24" || fail "no route to 10.1.0.0/24"
$N0 ip -4 route show dev veth0 | grep -q "^10.9.0.0/24" || fail "no route to 10.9.0.0/24"
if $N0 ip -4 route show | grep -q "^10.2.0.0/24"; then
  fail "route to 10.2.0.0/24 restored"
fi
$N0 ip -6 addr show dev veth0 | grep -q "2001:db8:9::1/64" || fail "no 2001:db8:9::1"
$N0 ip -6 route show dev veth0 | grep -q "^2001:db8:9::/64" || fail "no route to 2001:db8:9::/64"
if $N0 ip -6 addr show dev veth0 | grep -q "2001:db8:1::1"; then
  fail "IPv6 address restored"
fi
check_connectivity test1 10.1.0.2 8802 test0 "after up"

# The loopback device can go down too. ::1 is added again when it comes up.
had_ipv6_loopback=""
if $N0 ip -6 addr show dev lo | grep -q "::1/128"; then
  had_ipv6_loopback=1
fi
$N0 ip link set lo down
link_is_down test0 lo
$N0 ip -4 addr show dev lo | grep -q "127.0.0.1/8" || fail "127.0.0.1 removed"
if $N0 ip -6 addr show dev lo | grep -q "::1/128"; then
  fail "::1 not removed"
fi
$N0 ip link set lo up
link_is_up test0 lo
if [[ -n "$had_ipv6_loopback" ]]; then
  $N0 ip -6 addr show dev lo | grep -q "::1/128" || fail "::1 not restored"
fi
[[ "$(probe_tcp test0 127.0.0.1)" == reachable ]] || fail "127.0.0.1 not reachable after lo up"

# A bridge port that is down, and a bridge that is down, forward nothing.
ip netns add test2
N2="ip netns exec test2"
$N2 ip link set lo up
$N0 ip link add br0 type bridge
ip link add veth4 netns test0 type veth peer name veth5 netns test1
ip link add veth6 netns test0 type veth peer name veth7 netns test2
$N0 ip link set veth4 master br0
$N0 ip link set veth6 master br0
for dev in br0 veth4 veth6; do
  $N0 ip link set "$dev" up
done
$N1 ip link set veth5 up
$N2 ip link set veth7 up
$N0 ip addr add 10.3.0.1/24 dev br0
$N1 ip addr add 10.3.0.2/24 dev veth5
$N2 ip addr add 10.3.0.3/24 dev veth7
[[ "$(probe_tcp test0 10.3.0.2)" == reachable ]] || fail "10.3.0.2 not reachable through br0"
[[ "$(probe_tcp test1 10.3.0.3)" == reachable ]] || fail "10.3.0.3 not reachable from test1"
$N0 ip link set veth4 down
res="$(probe_tcp test0 10.3.0.2)"
[[ "$res" == timeout ]] || fail "10.3.0.2 through a port that is down: $res"
$N0 ip link set veth4 up
[[ "$(probe_tcp test1 10.3.0.3)" == reachable ]] || fail "10.3.0.3 not reachable after port up"
$N0 ip link set veth6 down
res="$(probe_tcp test1 10.3.0.3)"
[[ "$res" == timeout ]] || fail "10.3.0.3 behind a port that is down: $res"
$N0 ip link set veth6 up
[[ "$(probe_tcp test1 10.3.0.3)" == reachable ]] || fail "10.3.0.3 not reachable after port up"
$N0 ip link set br0 down
res="$(probe_tcp test1 10.3.0.3)"
[[ "$res" == timeout ]] || fail "10.3.0.3 through a bridge that is down: $res"
$N0 ip link set br0 up
[[ "$(probe_tcp test1 10.3.0.3)" == reachable ]] || fail "10.3.0.3 not reachable after bridge up"
ip netns del test2

# A link that is down stays down when it moves to another namespace.
$N0 ip link add veth2 type veth peer name veth3
$N0 ip link set veth2 up
$N0 ip link set veth2 down
$N0 ip link set veth2 netns test1
link_is_down test1 veth2

ip netns del test0
ip netns del test1
