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

# Checks that a service address DNATed in the netns of a bridge is reachable
# from the hosts on the bridge, including the host the service is DNATed to,
# when bridged frames go through iptables (bridge-nf-call-iptables and
# bridge-nf-call-ip6tables), and that the FORWARD chain filters them.

set -xeo pipefail
source "$(dirname "$0")/rtnetlink_test.sh"
TCP_SRV="$(dirname "$0")/tcp_serv"
if [[ ! -f "$TCP_SRV" ]]; then
  TCP_SRV="$(dirname "$0")/tcp_serv_/tcp_serv"
fi

# The iptables tools are installed in sbin, which the test environment's PATH
# may not include.
export PATH="${PATH}:/usr/sbin:/sbin"
IPT=iptables-legacy
IP6T=ip6tables-legacy
if ! which "$IPT" "$IP6T"; then
  IPT=iptables
  IP6T=ip6tables
fi

# start_server starts TCP_SRV in a network namespace and sets srv_pid.
# Arguments:
# * network namespace where the server will be started
# * port to listen on
# * message that will be sent to the client
# * other arguments of TCP_SRV
start_server() {
  exec {pipe}<> <(:)
  exec {pipe_r}</proc/self/fd/$pipe
  exec {pipe_w}>/proc/self/fd/$pipe
  exec {pipe}>&-
  echo "$3" | ip netns exec "$1" "$TCP_SRV" "--port=$2" "--sync-fd=$pipe_w" "${@:4}" 1>&2 &
  srv_pid=$!
  exec {pipe_w}>&-
  cat <&$pipe_r
  exec {pipe_r}>&-
}

# check_service checks that a TCP connection to a service address reaches the
# server it is DNATed to.
# Arguments:
# * network namespace of the server
# * port of the server
# * network namespace of the client
# * service address
# * service port
# * test message
check_service() {
  start_server "$1" "$2" "$6"
  out=$(ip netns exec "$3" timeout 10 nc -nvd "$4" "$5")
  if [[ "$out" != "$6" ]]; then
    fail "unexpected output '$out' (expected '$6')"
  fi
  wait "$srv_pid"
}

# check_no_service checks that a TCP connection to a service address fails.
# Arguments are the same as for check_service.
check_no_service() {
  start_server "$1" "$2" "$6"
  if out=$(ip netns exec "$3" timeout 5 nc -nvd "$4" "$5") && [[ -n "$out" ]]; then
    fail "unexpected output '$out' (expected no connection)"
  fi
  kill "$srv_pid"
  wait "$srv_pid" || true
}

# check_udp_service checks that a UDP datagram to a service address reaches the
# server it is DNATed to, and that the client gets the reply of the server
# from the service address. Arguments are the same as for check_service.
check_udp_service() {
  start_server "$1" "$2" "$6" --udp
  out=$(echo request | ip netns exec "$3" timeout 10 nc -nu -w 2 "$4" "$5")
  if [[ "$out" != "$6" ]]; then
    fail "unexpected output '$out' (expected '$6')"
  fi
  wait "$srv_pid"
}

# check_no_udp_service checks that a client doesn't get a reply to a UDP
# datagram to a service address from the service address. Arguments are the
# same as for check_service.
check_no_udp_service() {
  start_server "$1" "$2" "$6" --udp
  if out=$(echo request | ip netns exec "$3" timeout 5 nc -nu -w 2 "$4" "$5") && [[ -n "$out" ]]; then
    fail "unexpected output '$out' (expected no reply)"
  fi
  kill "$srv_pid" || true
  wait "$srv_pid" || true
}

ip netns attach rootns "$$"
if [[ ! -d /proc/sys/net/bridge ]]; then
  echo "SKIP: /proc/sys/net/bridge doesn't exist, bridge netfilter isn't available; no test was run." >&2
  exit 0
fi
if ! "$IPT" -t nat -L >/dev/null || ! "$IP6T" -t nat -L >/dev/null; then
  echo "SKIP: the iptables nat table isn't available; no test was run." >&2
  exit 0
fi

ip link add br0 type bridge
ip netns add test0
ip netns add test1
ip link add hveth0 type veth peer name veth0 netns test0
ip link add hveth1 type veth peer name veth1 netns test1
ip link set hveth0 master br0
ip link set hveth1 master br0
bridge link set dev hveth1 hairpin on
ip link set up dev hveth0
ip link set up dev hveth1
ip addr add 192.168.0.3/24 dev br0
ip addr add fd00::3/64 dev br0 nodad
ip link set up dev br0
for i in 0 1; do
  # The server listens on IPv6 only if it can use the IPv6 loopback address.
  ip netns exec "test$i" ip link set up dev lo
  ip netns exec "test$i" ip link set up dev "veth$i"
  ip netns exec "test$i" ip addr add "192.168.0.$((i + 1))/24" dev "veth$i"
  ip netns exec "test$i" ip addr add "fd00::$((i + 1))/64" dev "veth$i" nodad
  ip netns exec "test$i" ip route add default via 192.168.0.3
  ip netns exec "test$i" ip -6 route add default via fd00::3
done
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

"$IPT" -t nat -A PREROUTING -d 10.96.0.10 -p tcp --dport 80 -j DNAT --to-destination 192.168.0.2:8800
"$IPT" -t nat -A POSTROUTING -s 192.168.0.2 -d 192.168.0.2 -j MASQUERADE
"$IP6T" -t nat -A PREROUTING -d fd00:96::10 -p tcp --dport 80 -j DNAT --to-destination "[fd00::2]:8800"
"$IP6T" -t nat -A POSTROUTING -s fd00::2 -d fd00::2 -j MASQUERADE
"$IPT" -t nat -A PREROUTING -d 10.96.0.10 -p udp --dport 81 -j DNAT --to-destination 192.168.0.2:8801
"$IP6T" -t nat -A PREROUTING -d fd00:96::10 -p udp --dport 81 -j DNAT --to-destination "[fd00::2]:8801"

# Without bridge netfilter, the reply of the server goes straight to the
# client, which doesn't know it as the service.
echo 0 > /proc/sys/net/bridge/bridge-nf-call-iptables
echo 0 > /proc/sys/net/bridge/bridge-nf-call-ip6tables
check_no_service test1 8800 test0 10.96.0.10 80 "IPv4 service without bridge netfilter"
check_no_service test1 8800 test0 fd00:96::10 80 "IPv6 service without bridge netfilter"
check_no_udp_service test1 8801 test0 10.96.0.10 81 "IPv4 UDP service without bridge netfilter"
check_no_udp_service test1 8801 test0 fd00:96::10 81 "IPv6 UDP service without bridge netfilter"

echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables
echo 1 > /proc/sys/net/bridge/bridge-nf-call-ip6tables
check_service test1 8800 test0 10.96.0.10 80 "IPv4 service from test0"
check_service test1 8800 test1 10.96.0.10 80 "IPv4 service from test1"
check_service test1 8800 test0 fd00:96::10 80 "IPv6 service from test0"
check_service test1 8800 test1 fd00:96::10 80 "IPv6 service from test1"
check_udp_service test1 8801 test0 10.96.0.10 81 "IPv4 UDP service from test0"
check_udp_service test1 8801 test1 10.96.0.10 81 "IPv4 UDP service from test1"
check_udp_service test1 8801 test0 fd00:96::10 81 "IPv6 UDP service from test0"
check_udp_service test1 8801 test1 fd00:96::10 81 "IPv6 UDP service from test1"

# The FORWARD chain sees bridged frames. With the policy DROP, only the
# connections it accepts as NEW get through, and the replies are accepted as
# ESTABLISHED.
"$IPT" -P FORWARD DROP
"$IPT" -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
"$IP6T" -P FORWARD DROP
"$IP6T" -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
"$IP6T" -A FORWARD -p icmpv6 -j ACCEPT
check_no_service test1 8800 test0 10.96.0.10 80 "IPv4 service with FORWARD policy DROP"
check_no_service test1 8800 test0 fd00:96::10 80 "IPv6 service with FORWARD policy DROP"
"$IPT" -A FORWARD -m conntrack --ctstate NEW -d 192.168.0.2 -p tcp --dport 8800 -j ACCEPT
"$IP6T" -A FORWARD -m conntrack --ctstate NEW -d fd00::2 -p tcp --dport 8800 -j ACCEPT
check_service test1 8800 test0 10.96.0.10 80 "IPv4 service accepted by FORWARD"
check_service test1 8800 test1 10.96.0.10 80 "IPv4 service accepted by FORWARD from test1"
check_service test1 8800 test0 fd00:96::10 80 "IPv6 service accepted by FORWARD"
check_service test1 8800 test1 fd00:96::10 80 "IPv6 service accepted by FORWARD from test1"
"$IPT" -P FORWARD ACCEPT
"$IPT" -F FORWARD
"$IP6T" -P FORWARD ACCEPT
"$IP6T" -F FORWARD

ip netns del test0
ip netns del test1
ip link del br0
