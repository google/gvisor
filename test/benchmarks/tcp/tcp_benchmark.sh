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
iperf_version_arg=

# Defaults; this provides a reasonable approximation of a decent internet link.
# Parameters can be varied independently from this set to see response to
# various changes in the kind of link available.
client=false
server=false
verbose=false
gso=0
swgso=false
mtu=1280                # 1280 is a reasonable lowest-common-denominator.
latency=10              # 10ms approximates a fast, dedicated connection.
latency_variation=1     # +/- 1ms is a relatively low amount of jitter.
loss=0.1                # 0.1% loss is non-zero, but not extremely high.
duplicate=0.1           # 0.1% means duplicates are 1/10x as frequent as losses.
duration=30             # 30s is enough time to consistent results (experimentally).
helper_dir="$(dirname "$0")"
netstack_opts=
disable_linux_gso=
disable_linux_gro=
gro=0
num_client_threads=1

# Check for netem support.
lsmod_output=$(lsmod | grep sch_netem)
if [[ "$?" != "0" ]]; then
  echo "warning: sch_netem may not be installed." >&2
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client)
      client=true
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
    --cpuprofile)
      shift
      netstack_opts="${netstack_opts} -cpuprofile=$1"
      ;;
    --memprofile)
      shift
      netstack_opts="${netstack_opts} -memprofile=$1"
      ;;
    --blockprofile)
      shift
      netstack_opts="${netstack_opts} -blockprofile=$1"
      ;;
    --mutexprofile)
      shift
      netstack_opts="${netstack_opts} -mutexprofile=$1"
      ;;
    --traceprofile)
      shift
      netstack_opts="${netstack_opts} -traceprofile=$1"
      ;;
    --disable-linux-gso)
      disable_linux_gso=1
      ;;
    --disable-linux-gro)
      disable_linux_gro=1
      ;;
    --gro)
      shift
      [[ "$#" -le 0 ]] && echo "no GRO timeout provided" && exit 1
      gro=$1
      ;;
    --ipv6)
      client_addr=fd::1
      client_proxy_addr=fd::2
      server_proxy_addr=fd::3
      server_addr=fd::4
      full_server_addr=[${server_addr}]:${iperf_port}
      full_server_proxy_addr=[${server_proxy_addr}]:${proxy_port}
      iperf_version_arg=-V
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
    *)
      echo "unknown option: $1"
      echo ""
      echo "usage: $0 [options]"
      echo "options:"
      echo " --help                show this message"
      echo " --verbose             verbose output"
      echo " --client              use netstack as the client"
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
      echo " --helpers             set the helper directory"
      echo " --num-client-threads  number of parallel client threads to run"
      echo " --disable-linux-gso   disable segmentation offload (TSO, GSO, GRO) in the Linux network stack"
      echo " --disable-linux-gro   disable GRO in the Linux network stack"
      echo " --gro                 set gVisor GRO timeout"
      echo " --ipv6                use ipv6 for benchmarks"
      echo ""
      echo "The output will of the script will be:"
      echo "  <throughput> <client-cpu-usage> <server-cpu-usage>"
      exit 1
  esac
  shift
done

if [[ ${verbose} == "true" ]]; then
  set -x
fi

# Latency needs to be halved, since it's applied on both ways.
half_latency=$(echo "${latency}"/2 | bc -l | awk '{printf "%1.2f", $0}')
half_loss=$(echo "${loss}"/2 | bc -l | awk '{printf "%1.6f", $0}')
half_duplicate=$(echo "${duplicate}"/2 | bc -l | awk '{printf "%1.6f", $0}')
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

# Client proxy that will listen on the client's iperf target forward traffic
# using the host networking stack.
client_args="${proxy_binary} -port ${proxy_port} -forward ${full_server_proxy_addr}"
if ${client}; then
  # Client proxy that will listen on the client's iperf target
  # and forward traffic using netstack.
  client_args="${proxy_binary} ${netstack_opts} -port ${proxy_port} -client \\
      -mtu ${mtu} -iface client.0 -addr ${client_proxy_addr} -mask ${mask} \\
      -forward ${full_server_proxy_addr} -gso=${gso} -swgso=${swgso} --gro=${gro}"
fi

# Server proxy that will listen on the proxy port and forward to the server's
# iperf server using the host networking stack.
server_args="${proxy_binary} -port ${proxy_port} -forward ${full_server_addr}"
if ${server}; then
  # Server proxy that will listen on the proxy port and forward to the servers'
  # iperf server using netstack.
  server_args="${proxy_binary} ${netstack_opts} -port ${proxy_port} -server \\
      -mtu ${mtu} -iface server.0 -addr ${server_proxy_addr} -mask ${mask} \\
      -forward ${full_server_addr} -gso=${gso} -swgso=${swgso} --gro=${gro}"
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

exec unshare -U -m -n -r -f -p --mount-proc /bin/bash << EOF
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

# Add appropriate latency, loss and duplication.
#
# This is added in at the point of bridge connection.
for device in wan.0 wan.1; do
  # NOTE: We don't support a loss correlation as testing has shown that it
  # actually doesn't work. The man page actually has a small comment about this
  # "It is also possible to add a correlation, but this option is now deprecated
  # due to the noticed bad behavior." For more information see netem(8).
  tc qdisc add dev \$device root netem \\
    delay ${half_latency}ms ${latency_variation}ms ${distribution} \\
    ${loss_opt} ${duplicate_opt}
done

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
  ${nsjoin_binary} /tmp/client.netns ip addr add ${client_proxy_addr}/${mask} dev client.0
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
  ${nsjoin_binary} /tmp/server.netns ip addr add ${server_proxy_addr}/${mask} dev server.0
fi

# Add client and server addresses, and bring everything up.
${nsjoin_binary} /tmp/client.netns ip addr add ${client_addr}/${mask} dev client.0
${nsjoin_binary} /tmp/server.netns ip addr add ${server_addr}/${mask} dev server.0
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
${nsjoin_binary} /tmp/client.netns ip link set client.0 up
${nsjoin_binary} /tmp/client.netns ip link set lo up
${nsjoin_binary} /tmp/server.netns ip link set server.0 up
${nsjoin_binary} /tmp/server.netns ip link set lo up
ip link set dev client.1 up
ip link set dev server.1 up

${nsjoin_binary} /tmp/server.netns ${server_args} &
server_pid=\$!

# Start the iperf server.
${nsjoin_binary} /tmp/server.netns iperf ${iperf_version_arg} -p ${iperf_port} -s >&2 &
iperf_pid=\$!

# Give services time to start.
sleep 5

${nsjoin_binary} /tmp/client.netns ${client_args} &
client_pid=\$!

# Show traffic information.
if ! ${client} && ! ${server}; then
  ${nsjoin_binary} /tmp/client.netns ping -c 100 -i 0.001 -W 1 ${server_addr} >&2 || true
fi

results_file=\$(mktemp)
function cleanup {
  rm -f \$results_file
  kill -TERM \$client_pid
  kill -TERM \$server_pid
  wait \$client_pid
  wait \$server_pid
  kill -9 \$iperf_pid 2>/dev/null
}

# Allow failure from this point.
set +e
trap cleanup EXIT

# Run the benchmark, recording the results file.
while ${nsjoin_binary} /tmp/client.netns iperf \\
    ${iperf_version_arg} -p ${proxy_port} -c ${client_addr} -t ${duration} -f m -P ${num_client_threads} 2>&1 \\
    | tee \$results_file \\
    | grep "connect failed" >/dev/null; do
  sleep 0.1 # Wait for all services.
done

# Unlink all relevant devices from the bridge. This is because when the bridge
# is deleted, the kernel may hang. It appears that this problem is fixed in
# upstream commit 1ce5cce895309862d2c35d922816adebe094fe4a.
ip link set client.1 nomaster
ip link set server.1 nomaster
ip link set wan.0 nomaster
ip link set wan.1 nomaster

# Emit raw results.
cat \$results_file >&2

# Emit a useful result (final throughput).
mbits=\$(grep Mbits/sec \$results_file \\
  | sed -n -e 's/^.*[[:space:]]\\([[:digit:]]\\+\\(\\.[[:digit:]]\\+\\)\\?\\)[[:space:]]*Mbits\\/sec.*/\\1/p')
client_cpu_ticks=\$(cat /proc/\$client_pid/stat \\
  | awk '{print (\$14+\$15);}')
server_cpu_ticks=\$(cat /proc/\$server_pid/stat \\
  | awk '{print (\$14+\$15);}')
ticks_per_sec=\$(getconf CLK_TCK)
client_cpu_load=\$(bc -l <<< \$client_cpu_ticks/\$ticks_per_sec/${duration})
server_cpu_load=\$(bc -l <<< \$server_cpu_ticks/\$ticks_per_sec/${duration})
echo \$mbits \$client_cpu_load \$server_cpu_load
EOF
