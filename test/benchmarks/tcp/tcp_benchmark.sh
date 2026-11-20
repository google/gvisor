#!/bin/bash

# Copyright 2018 The gVisor Authors.
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

# TCP benchmark; see README.md for documentation.

# Fixed parameters.
iperf_port=45201 # Not likely to be privileged.
proxy_port=44000 # Ditto.
mask=8
client_addr=10.0.0.1
client_proxy_addr=10.0.0.2
server_proxy_addr=10.0.0.3
server_addr=10.0.0.4
full_server_addr=${server_addr}:${iperf_port}
full_server_proxy_addr=${server_proxy_addr}:${proxy_port}
iperf_binary_name=iperf3
iperf_version_arg=
addr_opts=

# Defaults; this provides a reasonable approximation of a decent internet link.
# Parameters can be varied independently from this set to see response to
# various changes in the kind of link available.
client=false
server=false
linux_client=false
verbose=false
gso=0
swgso=false
mtu=1280                # 1280 is a reasonable lowest-common-denominator.
latency=10              # 10ms approximates a fast, dedicated connection.
latency_variation=1     # +/- 1ms is a relatively low amount of jitter.
loss=0.1                # 0.1% loss is non-zero, but not extremely high.
duplicate=0.1           # 0.1% means duplicates are 1/10x as frequent as losses.
reorder=0               # No reordering other than what the jitter causes.
rate=0                  # No bottleneck.
queue=                  # Empty means one bandwidth-delay product (minimum 20 packets).
ecn=false               # The bottleneck queue drops packets and does not mark them.
duration=30             # 30s is enough time to consistent results (experimentally).
helper_dir="$(dirname "$0")"
netstack_opts=
netstack_cc=reno
disable_linux_gso=
disable_linux_gro=
gro=false
num_client_threads=1
sniff=false
xdp=false
declare -a unshare_opts=( -U -r )

# Check for netem support.
lsmod_output=$(lsmod | grep sch_netem)
if [[ "$?" != "0" ]]; then
  echo "warning: sch_netem may not be installed." >&2
fi

function checktmp() {
  if [[ "$1" =~ ^/tmp/ ]]; then
    echo "Don't use /tmp for output files ('$1') -- tcp_benchmark mounts over /tmp and your file will never make it to the root /tmp."
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client)
      client=true
      ;;
    --linux-client)
      linux_client=true
      ;;
    --client_tcp_probe_file)
      shift
      netstack_opts="${netstack_opts} -client_tcp_probe_file=$1"
      ;;
    --server)
      server=true
      ;;
    --verbose)
      verbose=true
      ;;
    --gso)
      shift
      gso=$1
      ;;
    --swgso)
      swgso=true
      ;;
    --server_tcp_probe_file)
      shift
      netstack_opts="${netstack_opts} -server_tcp_probe_file=$1"
      ;;
    --ideal)
      mtu=1500            # Standard ethernet.
      latency=0           # No latency.
      latency_variation=0 # No jitter.
      loss=0              # No loss.
      duplicate=0         # No duplicates.
      reorder=0           # No reordering.
      rate=0              # No bottleneck.
      queue=              # Default queue length.
      ecn=false           # No ECN marks.
      ;;
    --mtu)
      shift
      [[ "$#" -le 0 ]] && echo "no mtu provided" && exit 1
      mtu=$1
      ;;
    --sack)
      netstack_opts="${netstack_opts} -sack"
      ;;
    --rack)
      netstack_opts="${netstack_opts} -rack"
      ;;
    --cubic)
      netstack_opts="${netstack_opts} -cubic"
      netstack_cc=cubic
      ;;
    --moderate-recv-buf)
      netstack_opts="${netstack_opts} -moderate_recv_buf"
      ;;
    --duration)
      shift
      [[ "$#" -le 0 ]] && echo "no duration provided" && exit 1
      duration=$1
      ;;
    --latency)
      shift
      [[ "$#" -le 0 ]] && echo "no latency provided" && exit 1
      latency=$1
      ;;
    --latency-variation)
      shift
      [[ "$#" -le 0 ]] && echo "no latency variation provided" && exit 1
      latency_variation=$1
      ;;
    --loss)
      shift
      [[ "$#" -le 0 ]] && echo "no loss probability provided" && exit 1
      loss=$1
      ;;
    --duplicate)
      shift
      [[ "$#" -le 0 ]] && echo "no duplicate provided" && exit 1
      duplicate=$1
      ;;
    --reorder)
      shift
      [[ "$#" -le 0 ]] && echo "no reorder probability provided" && exit 1
      reorder=$1
      ;;
    --rate)
      shift
      [[ "$#" -le 0 ]] && echo "no rate provided" && exit 1
      rate=$1
      ;;
    --queue)
      shift
      [[ "$#" -le 0 ]] && echo "no queue length provided" && exit 1
      queue=$1
      ;;
    --ecn)
      ecn=true
      ;;
    --cpuprofile)
      shift
      netstack_opts="${netstack_opts} -cpuprofile=$1"
      checktmp "$1"
      ;;
    --memprofile)
      shift
      netstack_opts="${netstack_opts} -memprofile=$1"
      checktmp "$1"
      ;;
    --blockprofile)
      shift
      netstack_opts="${netstack_opts} -blockprofile=$1"
      checktmp "$1"
      ;;
    --mutexprofile)
      shift
      netstack_opts="${netstack_opts} -mutexprofile=$1"
      checktmp "$1"
      ;;
    --traceprofile)
      shift
      netstack_opts="${netstack_opts} -traceprofile=$1"
      checktmp "$1"
      ;;
    --disable-linux-gso)
      disable_linux_gso=1
      ;;
    --disable-linux-gro)
      disable_linux_gro=1
      ;;
    --gro)
      gro=true
      ;;
    --ipv6)
      client_addr=fd::1
      client_proxy_addr=fd::2
      server_proxy_addr=fd::3
      server_addr=fd::4
      full_server_addr=[${server_addr}]:${iperf_port}
      full_server_proxy_addr=[${server_proxy_addr}]:${proxy_port}
      iperf_version_arg=-V
      addr_opts=nodad
      netstack_opts="${netstack_opts} -ipv6"
      ;;
    --num-client-threads)
      shift
      num_client_threads=$1
      ;;
    --helpers)
      shift
      [[ "$#" -le 0 ]] && echo "no helper dir provided" && exit 1
      helper_dir=$1
      ;;
    --iperf-binary)
      shift
      [[ "$#" -le 0 ]] && echo "no iperf name provided" && exit 1
      iperf_binary_name=$1
      ;;
    --sniff)
      netstack_opts="${netstack_opts} -sniff"
      ;;
    --xdp)
      xdp=true
      ;;
    --no-user-ns)
      unshare_opts=()
      ;;
    *)
      echo "unknown option: $1"
      echo ""
      echo "usage: $0 [options]"
      echo "options:"
      echo " --help                show this message"
      echo " --verbose             verbose output"
      echo " --client              use netstack as the client"
      echo " --linux-client        print client stats in linux case"
      echo " --ideal               reset all network emulation"
      echo " --server              use netstack as the server"
      echo " --mtu                 set the mtu (bytes)"
      echo " --sack                enable SACK support"
      echo " --rack                enable RACK support"
      echo " --moderate-recv-buf   enable TCP receive buffer auto-tuning"
      echo " --cubic               enable CUBIC congestion control for Netstack"
      echo " --duration            set the test duration (s)"
      echo " --latency             set the latency (ms)"
      echo " --latency-variation   set the latency variation"
      echo " --loss                set the loss probability (%)"
      echo " --duplicate           set the duplicate probability (%)"
      echo " --reorder             set the reorder probability (%); a reordered packet skips"
      echo "                       the latency; requires a non-zero --latency"
      echo " --rate                set the bottleneck rate (Mbit/s); 0 means no bottleneck"
      echo " --queue               set the bottleneck queue length (packets); the default is"
      echo "                       one bandwidth-delay product, and not less than 20 packets;"
      echo "                       requires --rate"
      echo " --ecn                 use a CoDel bottleneck queue that marks ECN-capable packets"
      echo "                       and enable ECN in the Linux network stack; requires --rate"
      echo " --helpers             set the helper directory"
      echo " --num-client-threads  number of parallel client threads to run"
      echo " --disable-linux-gso   disable segmentation offload (TSO, GSO) in the Linux network stack"
      echo " --disable-linux-gro   disable GRO in the Linux network stack"
      echo " --gso                 set the maximum size of a netstack GSO packet (bytes); 0 means"
      echo "                       no netstack GSO; the Linux network stack segments the packet"
      echo " --swgso               make netstack segment the GSO packet; requires --gso"
      echo " --gro                 enable gVisor GRO"
      echo " --ipv6                use ipv6 for benchmarks"
      echo " --iperf-binary        name of the iperf binary to call"
      echo " --sniff               sniff and output packet logs"
      echo " --xdp                 use AF_XDP socket instead of AF_PACKET"
      echo " --no-user-ns          don't run in a new user namespace. Useful for testing as root"
      echo ""
      echo "The output of the script is one line in the Go benchmark format:"
      echo "  BenchmarkTCP/<parameters> 1 <throughput> Mb/s <cpu-usage> cpu-time <sender-retransmits> retransmits"
      exit 1
  esac
  shift
done

if [[ ${verbose} == "true" ]]; then
  set -x
fi

if ! [[ "${duration}" =~ ^0*[1-9][0-9]{0,4}$ ]] || (( 10#${duration} > 86400 )); then
  echo "invalid duration: ${duration}" >&2
  exit 1
fi
duration=$((10#${duration}))

# Latency needs to be halved, since it's applied on both ways.
half_latency=$(echo "${latency}"/2 | bc -l | awk '{printf "%1.2f", $0}')
half_loss=$(echo "${loss}"/2 | bc -l | awk '{printf "%1.6f", $0}')
half_duplicate=$(echo "${duplicate}"/2 | bc -l | awk '{printf "%1.6f", $0}')
half_reorder=$(echo "${reorder}"/2 | bc -l | awk '{printf "%1.6f", $0}')
# Per-attempt deadline for the iperf client (seconds).
client_timeout=$((duration + 60))
# The iperf port as it appears in /proc/net/tcp (4 uppercase hex digits).
iperf_port_hex=$(printf '%04X' "${iperf_port}")
helper_dir="${helper_dir#$(pwd)/}" # Use relative paths.
proxy_binary="${helper_dir}/tcp_proxy"
nsjoin_binary="${helper_dir}/nsjoin"

if [[ ! -e ${proxy_binary} ]]; then
  echo "Could not locate ${proxy_binary}, please make sure you've built the binary"
  exit 1
fi

if [[ ! -e ${nsjoin_binary} ]]; then
  echo "Could not locate ${nsjoin_binary}, please make sure you've built the binary"
  exit 1
fi

if [[ "$(echo "${latency_variation}" | awk '{printf "%1.2f", $0}')" != "0.00" ]]; then
  # As long as there's some jitter, then we use the paretonormal distribution.
  # This will preserve the minimum RTT, but add a realistic amount of jitter to
  # the connection and cause re-ordering, etc. The regular pareto distribution
  # appears to an unreasonable level of delay (we want only small spikes.)
  distribution="distribution paretonormal"
else
  distribution=""
fi

if [[ ! "${rate}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "--rate must be a number (Mbit/s)" >&2
  exit 1
fi
if [[ -n "${queue}" && ! "${queue}" =~ ^([2-9]|[1-9][0-9]+)$ ]]; then
  echo "--queue must be a number of packets, and not less than 2" >&2
  exit 1
fi

# The bottleneck is a bounded queue that a token bucket drains at the rate.
bottleneck=false
if [[ "$(echo "${rate}" | bc -q)" != "0" ]]; then
  bottleneck=true
  if [[ -z "${queue}" ]]; then
    # One bandwidth-delay product, and not less than 20 packets.
    queue=$(awk -v rate="${rate}" -v latency="${latency}" -v mtu="${mtu}" \
      'BEGIN { q = rate * 125 * latency / mtu; if (q < 20) q = 20; printf "%d", q }')
  fi
  # The bucket holds 4ms of traffic, not more than the queue and not less than
  # two packets. The token bucket segments a GSO packet that is larger than the
  # bucket before the packet goes into the queue, so each packet fits in a
  # queue that has a limit in bytes.
  frame=$((mtu + 14)) # The queueing disciplines count the Ethernet header.
  burst=$(awk -v rate="${rate}" -v frame="${frame}" -v queue="${queue}" 'BEGIN {
    b = rate * 500
    if (b > queue * frame) b = queue * frame
    if (b < 2 * frame) b = 2 * frame
    printf "%d", b
  }')
  if ${ecn}; then
    # The CoDel interval is the round-trip time, and not less than 100ms.
    interval=$(awk -v latency="${latency}" \
      'BEGIN { i = latency; if (i < 100) i = 100; printf "%d", i }')
    queue_qdisc="codel limit ${queue} interval ${interval}ms ecn"
  else
    queue_qdisc="bfifo limit $((queue * frame))"
  fi
else
  if ${ecn} || [[ -n "${queue}" ]]; then
    echo "--ecn and --queue require --rate" >&2
    exit 1
  fi
  queue=0
fi

# Client proxy that will listen on the client's iperf target forward traffic
# using the host networking stack.
client_args="${proxy_binary} -port ${proxy_port} -forward ${full_server_proxy_addr} \\
    -retransmits_file=/tmp/client.retransmits"
if ${client}; then
  # Client proxy that will listen on the client's iperf target
  # and forward traffic using netstack.
  client_args="${proxy_binary} ${netstack_opts} -port ${proxy_port} -client \\
      -mtu ${mtu} -iface client.0 -addr ${client_proxy_addr} -mask ${mask} \\
      -forward ${full_server_proxy_addr} -gso=${gso} -swgso=${swgso} --gro=${gro} \\
      --xdp=${xdp} -retransmits_file=/tmp/client.retransmits"
fi

# Server proxy that will listen on the proxy port and forward to the server's
# iperf server using the host networking stack.
server_args="${proxy_binary} -port ${proxy_port} -forward ${full_server_addr}"
if ${server}; then
  # Server proxy that will listen on the proxy port and forward to the servers'
  # iperf server using netstack.
  server_args="${proxy_binary} ${netstack_opts} -port ${proxy_port} -server \\
      -mtu ${mtu} -iface server.0 -addr ${server_proxy_addr} -mask ${mask} \\
      -forward ${full_server_addr} -gso=${gso} -swgso=${swgso} --gro=${gro} \\
      --xdp=${xdp}"
fi

# Specify loss and duplicate parameters only if they are non-zero
loss_opt=""
if [[ "$(echo "$half_loss" | bc -q)" != "0" ]]; then
  loss_opt="loss random ${half_loss}%"
fi
duplicate_opt=""
if [[ "$(echo "$half_duplicate" | bc -q)" != "0" ]]; then
  duplicate_opt="duplicate ${half_duplicate}%"
fi
reorder_opt=""
if [[ "$(echo "$half_reorder" | bc -q)" != "0" ]]; then
  if [[ "$(echo "$half_latency" | bc -q)" == "0" ]]; then
    echo "--reorder requires a non-zero --latency" >&2
    exit 1
  fi
  reorder_opt="reorder ${half_reorder}%"
fi

exec unshare "${unshare_opts[@]}" -m -n -f -p --mount-proc /bin/bash << EOF
set -e -m

if [[ ${verbose} == "true" ]]; then
  set -x
fi

mount -t tmpfs netstack-bench /tmp

# We may have reset the path in the unshare if the shell loaded some public
# profiles. Ensure that tools are discoverable via the parent's PATH.
export PATH=${PATH}

# Add client, server interfaces.
ip link add client.0 type veth peer name client.1
ip link add server.0 type veth peer name server.1

# Add network emulation devices.
ip link add wan.0 type veth peer name wan.1
ip link set wan.0 up
ip link set wan.1 up

results_file=
iperf_pid=
server_pid=
client_pid=
function cleanup() {
  set +e
  if [[ -n "\${results_file}" ]]; then
    rm -f "\${results_file}"
  fi
  if [[ -n "\${client_pid}" ]]; then
    kill -TERM "\${client_pid}" 2>/dev/null
    wait "\${client_pid}"
  fi
  if [[ -n "\${server_pid}" ]]; then
    kill -TERM "\${server_pid}" 2>/dev/null
    wait "\${server_pid}"
  fi
  if [[ -n "\${iperf_pid}" ]]; then
    kill -9 "\${iperf_pid}" 2>/dev/null
  fi
  # Unlink all relevant devices from the bridge. This is because when the bridge
  # is deleted, the kernel may hang. It appears that this problem is fixed in
  # upstream commit 1ce5cce895309862d2c35d922816adebe094fe4a.
  ip link set client.1 nomaster 2>/dev/null
  ip link set server.1 nomaster 2>/dev/null
  ip link set wan.0 nomaster 2>/dev/null
  ip link set wan.1 nomaster 2>/dev/null
}
trap cleanup EXIT

# Enroll on the bridge.
ip link add name br0 type bridge
ip link add name br1 type bridge
ip link set client.1 master br0
ip link set server.1 master br1
ip link set wan.0 master br0
ip link set wan.1 master br1
ip link set br0 up
ip link set br1 up

# Set the MTU appropriately.
ip link set client.0 mtu ${mtu}
ip link set server.0 mtu ${mtu}
ip link set wan.0 mtu ${mtu}
ip link set wan.1 mtu ${mtu}

# Add appropriate latency, loss, duplication and reordering.
#
# This is added in at the point of bridge connection.
for device in wan.0 wan.1; do
  # NOTE: We don't support a loss correlation as testing has shown that it
  # actually doesn't work. The man page actually has a small comment about this
  # "It is also possible to add a correlation, but this option is now deprecated
  # due to the noticed bad behavior." For more information see netem(8).
  #
  # The limit is large so that netem drops only the packets that the loss
  # probability selects, at any throughput and latency.
  tc qdisc add dev \$device root netem limit 1000000 \\
    delay ${half_latency}ms ${latency_variation}ms ${distribution} \\
    ${loss_opt} ${duplicate_opt} ${reorder_opt}
done

# Add the bottleneck. A packet goes through it after the network emulation.
if ${bottleneck}; then
  for device in client.1 server.1; do
    tc qdisc add dev \$device root handle 1: tbf \\
      rate ${rate}mbit burst ${burst} limit ${burst}
    tc qdisc add dev \$device parent 1:1 handle 10: ${queue_qdisc}
  done
fi

# Start a client proxy.
touch /tmp/client.netns
unshare -n mount --bind /proc/self/ns/net /tmp/client.netns

# Move the endpoint into the namespace.
while ip link | grep client.0 > /dev/null; do
  ip link set dev client.0 netns /tmp/client.netns
done

if ! ${client}; then
  # Only add the address to NIC if netstack is not in use. Otherwise the host
  # will also process the inbound SYN and send a RST back.
  ${nsjoin_binary} /tmp/client.netns ip addr add ${client_proxy_addr}/${mask} dev client.0 ${addr_opts}
fi

# Start a server proxy.
touch /tmp/server.netns
unshare -n mount --bind /proc/self/ns/net /tmp/server.netns
# Move the endpoint into the namespace.
while ip link | grep server.0 > /dev/null; do
  ip link set dev server.0 netns /tmp/server.netns
done
if ! ${server}; then
  # Only add the address to NIC if netstack is not in use. Otherwise the host
  # will also process the inbound SYN and send a RST back.
  ${nsjoin_binary} /tmp/server.netns ip addr add ${server_proxy_addr}/${mask} dev server.0 ${addr_opts}
fi

# Add client and server addresses, and bring everything up.
${nsjoin_binary} /tmp/client.netns ip addr add ${client_addr}/${mask} dev client.0 ${addr_opts}
${nsjoin_binary} /tmp/server.netns ip addr add ${server_addr}/${mask} dev server.0 ${addr_opts}
if [[ "${disable_linux_gso}" == "1" ]]; then
  ${nsjoin_binary} /tmp/client.netns ethtool -K client.0 tso off
  ${nsjoin_binary} /tmp/client.netns ethtool -K client.0 gso off
  ${nsjoin_binary} /tmp/server.netns ethtool -K server.0 tso off
  ${nsjoin_binary} /tmp/server.netns ethtool -K server.0 gso off
fi
if [[ "${disable_linux_gro}" == "1" ]]; then
  ${nsjoin_binary} /tmp/client.netns ethtool -K client.0 gro off
  ${nsjoin_binary} /tmp/server.netns ethtool -K server.0 gro off
fi
if ${ecn}; then
  # By default, the Linux network stack accepts ECN but does not request it.
  ${nsjoin_binary} /tmp/client.netns /bin/bash -c "echo 1 > /proc/sys/net/ipv4/tcp_ecn"
  ${nsjoin_binary} /tmp/server.netns /bin/bash -c "echo 1 > /proc/sys/net/ipv4/tcp_ecn"
fi
host_cc=\$(${nsjoin_binary} /tmp/client.netns cat /proc/sys/net/ipv4/tcp_congestion_control)
echo "Linux congestion control: \$host_cc" >&2
${nsjoin_binary} /tmp/client.netns ip link set client.0 up
${nsjoin_binary} /tmp/client.netns ip link set lo up
${nsjoin_binary} /tmp/server.netns ip link set server.0 up
${nsjoin_binary} /tmp/server.netns ip link set lo up
ip link set dev client.1 up
ip link set dev server.1 up

# Show traffic information before starting services.
if ! ${client} && ! ${server}; then
  ${nsjoin_binary} /tmp/client.netns ping -c 100 -i 0.001 -W 1 ${server_addr} >&2 || true
fi

results_file=\$(mktemp)

# Start the iperf server and wait (at most 10s) until its listening socket
# appears. Check /proc/net/tcp{,6} directly because a probe connection to the
# iperf control port can disrupt the server's control state.
${nsjoin_binary} /tmp/server.netns ${iperf_binary_name} ${iperf_version_arg} -p ${iperf_port} -s >&2 &
iperf_pid=\$!

server_ready=false
for ((i = 0; i < 100; i++)); do
  if ${nsjoin_binary} /tmp/server.netns cat /proc/net/tcp /proc/net/tcp6 2>/dev/null \\
      | awk '\$4 == "0A" { split(\$2, a, ":"); print a[2] }' \\
      | grep -q "^${iperf_port_hex}\$"; then
    server_ready=true
    break
  fi
  if ! kill -0 "\${iperf_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if [[ "\${server_ready}" != "true" ]]; then
  echo "iperf server failed to listen on port ${iperf_port}" >&2
  exit 1
fi

# Start both proxies back-to-back once the iperf server is listening; the server
# proxy dials the iperf server immediately on startup, starting its 10s cookie
# read timeout.
${nsjoin_binary} /tmp/server.netns ${server_args} &
server_pid=\$!

${nsjoin_binary} /tmp/client.netns ${client_args} &
client_pid=\$!

# Allow failure from this point.
set +e

# Run the benchmark, recording the results file. Retry connection refusal while
# the proxies finish starting (at most 600 tries or 60s), stopping immediately
# if any service exits. Bound each client attempt to ${client_timeout}s so a
# stalled transfer fails promptly.
connect_attempts=0
connect_deadline=\$((SECONDS + 60))
client_rc=0
while true; do
  ${nsjoin_binary} /tmp/client.netns timeout --kill-after=10 "${client_timeout}" \\
      ${iperf_binary_name} ${iperf_version_arg} -p ${proxy_port} -c ${client_addr} \\
      -t ${duration} -f m -P ${num_client_threads} >"\${results_file}" 2>&1
  client_rc=\$?
  if (( client_rc == 0 || client_rc == 124 || client_rc == 137 )); then
    break
  fi
  if ! kill -0 "\${client_pid}" 2>/dev/null || ! kill -0 "\${server_pid}" 2>/dev/null || ! kill -0 "\${iperf_pid}" 2>/dev/null; then
    break
  fi
  if ! grep -qE "connect failed|unable to connect to server" "\${results_file}"; then
    break
  fi
  if (( ++connect_attempts >= 600 || SECONDS >= connect_deadline )); then
    break
  fi
  sleep 0.1 # Wait for all services.
done

# Emit raw results and the state of the network emulation.
cat "\${results_file}" >&2
for device in wan.0 wan.1 client.1 server.1; do
  tc -s qdisc show dev \$device >&2
done

if (( client_rc == 124 || client_rc == 137 )); then
  echo "iperf client timed out after ${client_timeout}s" >&2
  exit 1
fi
if (( client_rc != 0 )); then
  echo "iperf client failed with exit status \${client_rc}" >&2
  exit 1
fi

# Emit the throughput from the receiver line of iperf. The sender line also
# counts the data that is in buffers and that the server did not receive. For
# multi-stream runs (-P > 1), iperf3 prints per-stream receiver lines followed
# by a [SUM] receiver line.
mbits=\$(awk '\$NF == "receiver" {
  for (i = 2; i <= NF; i++) {
    if (\$i == "Mbits/sec") {
      val = \$(i - 1)
    }
  }
}
END { print val }' "\${results_file}")
if [[ -z "\${mbits}" ]]; then
  echo "iperf client did not report receiver throughput" >&2
  exit 1
fi
client_cpu_ticks=\$(cat /proc/\$client_pid/stat \\
  | awk '{print (\$14+\$15);}')
server_cpu_ticks=\$(cat /proc/\$server_pid/stat \\
  | awk '{print (\$14+\$15);}')
ticks_per_sec=\$(getconf CLK_TCK)
client_cpu_load=\$(bc -l <<< \$client_cpu_ticks/\$ticks_per_sec/${duration})
server_cpu_load=\$(bc -l <<< \$server_cpu_ticks/\$ticks_per_sec/${duration})

# The iperf client sends the data, so the client proxy is the sender on the
# emulated path. It writes the number of retransmitted segments when it exits.
kill -TERM \$client_pid
wait \$client_pid
retransmits=\$(cat /tmp/client.retransmits)
if [[ -z "\${retransmits}" ]]; then
  echo "the client proxy did not report a retransmit count" >&2
  exit 1
fi

if ${client}; then
  sender=netstack-${netstack_cc}
else
  sender=linux-\$host_cc
fi
receiver=linux
if ${server}; then
  receiver=netstack
fi
role=server
cpu_load=\$server_cpu_load
if ${client} || ${linux_client}; then
  role=client
  cpu_load=\$client_cpu_load
fi
hostgso=true
if [[ "${disable_linux_gso}" ]]; then
  hostgso=false
fi
hostgro=true
if [[ "${disable_linux_gro}" ]]; then
  hostgro=false
fi
netstackgso=none
if { ${client} || ${server}; } && ! ${xdp} && [[ "${gso}" != "0" ]]; then
  netstackgso=host
  if ${swgso}; then
    netstackgso=gvisor
  fi
fi

name="BenchmarkTCP/sender=\$sender/receiver=\$receiver/role=\$role"
name="\$name/host-gso=\$hostgso/host-gro=\$hostgro/netstack-gso=\$netstackgso"
name="\$name/mtu=${mtu}/rtt=${latency}ms/jitter=${latency_variation}ms"
name="\$name/loss=${loss}/duplicate=${duplicate}/reorder=${reorder}"
name="\$name/rate=${rate}/queue=${queue}/ecn=${ecn}"
echo "\$name 1 \$mbits Mb/s \$cpu_load cpu-time \$retransmits retransmits"
EOF
