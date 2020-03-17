#!/bin/bash

# Copyright 2020 The gVisor Authors.
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

# Run a packetimpact test.  Two docker containers are made, one for the
# Device-Under-Test (DUT) and one for the test bench.  Each is attached with
# two networks, one for control packets that aid the test and one for test
# packets which are sent as part of the test and observed for correctness.

set -euxo pipefail

function failure() {
  local lineno=$1
  local msg=$2
  local filename="$0"
  echo "FAIL: $filename:$lineno: $msg"
}
trap 'failure ${LINENO} "$BASH_COMMAND"' ERR

declare -r LONGOPTS="dut_platform:,posix_server_binary:,testbench_binary:,runtime:,tshark"

# Don't use declare below so that the error from getopt will end the script.
PARSED=$(getopt --options "" --longoptions=$LONGOPTS --name "$0" -- "$@")

eval set -- "$PARSED"

while true; do
  case "$1" in
    --dut_platform)
      # Either "linux" or "netstack".
      declare -r DUT_PLATFORM="$2"
      shift 2
      ;;
    --posix_server_binary)
      declare -r POSIX_SERVER_BINARY="$2"
      shift 2
      ;;
    --testbench_binary)
      declare -r TESTBENCH_BINARY="$2"
      shift 2
      ;;
    --runtime)
      # Not readonly because there might be multiple --runtime arguments and we
      # want to use just the last one.  Only used if --dut_platform is
      # "netstack".
      declare RUNTIME="$2"
      shift 2
      ;;
    --tshark)
      declare -r TSHARK="1"
      shift 1
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Programming error"
      exit 3
  esac
done

# All the other arguments are scripts.
declare -r scripts="$@"

# Check that the required flags are defined in a way that is safe for "set -u".
if [[ "${DUT_PLATFORM-}" == "netstack" ]]; then
  if [[ -z "${RUNTIME-}" ]]; then
    echo "FAIL: Missing --runtime argument: ${RUNTIME-}"
    exit 2
  fi
  declare -r RUNTIME_ARG="--runtime ${RUNTIME}"
elif [[ "${DUT_PLATFORM-}" == "linux" ]]; then
  declare -r RUNTIME_ARG=""
else
  echo "FAIL: Bad or missing --dut_platform argument: ${DUT_PLATFORM-}"
  exit 2
fi
if [[ ! -f "${POSIX_SERVER_BINARY-}" ]]; then
  echo "FAIL: Bad or missing --posix_server_binary: ${POSIX_SERVER-}"
  exit 2
fi
if [[ ! -f "${TESTBENCH_BINARY-}" ]]; then
  echo "FAIL: Bad or missing --testbench_binary: ${TESTBENCH_BINARY-}"
  exit 2
fi

# Variables specific to the control network and interface start with CTRL_.
# Variables specific to the test network and interface start with TEST_.
# Variables specific to the DUT start with DUT_.
# Variables specific to the test bench start with TESTBENCH_.
# Use random numbers so that test networks don't collide.
declare -r CTRL_NET="ctrl_net-${RANDOM}${RANDOM}"
declare -r TEST_NET="test_net-${RANDOM}${RANDOM}"
# On both DUT and test bench, testing packets are on the eth2 interface.
declare -r TEST_DEVICE="eth2"
# Number of bits in the *_NET_PREFIX variables.
declare -r NET_MASK="24"
function new_net_prefix() {
  # Class C, 192.0.0.0 to 223.255.255.255, transitionally has mask 24.
  echo "$(shuf -i 192-223 -n 1).$(shuf -i 0-255 -n 1).$(shuf -i 0-255 -n 1)"
}
# Last bits of the DUT's IP address.
declare -r DUT_NET_SUFFIX=".10"
# Control port.
declare -r CTRL_PORT="40000"
# Last bits of the test bench's IP address.
declare -r TESTBENCH_NET_SUFFIX=".20"
declare -r TIMEOUT="60"
declare -r IMAGE_TAG="gcr.io/gvisor-presubmit/packetimpact"
# Make sure that docker is installed.
docker --version

function finish {
  local cleanup_success=1
  for net in "${CTRL_NET}" "${TEST_NET}"; do
    # Kill all processes attached to ${net}.
    for docker_command in "kill" "rm"; do
      (docker network inspect "${net}" \
        --format '{{range $key, $value := .Containers}}{{$key}} {{end}}' \
        | xargs -r docker "${docker_command}") || \
        cleanup_success=0
    done
    # Remove the network.
    docker network rm "${net}" || \
      cleanup_success=0
  done

  if ((!$cleanup_success)); then
    echo "FAIL: Cleanup command failed"
    exit 4
  fi
}
trap finish EXIT

# Subnet for control packets between test bench and DUT.
declare CTRL_NET_PREFIX=$(new_net_prefix)
while ! docker network create \
  "--subnet=${CTRL_NET_PREFIX}.0/${NET_MASK}" "${CTRL_NET}"; do
  sleep 0.1
  declare CTRL_NET_PREFIX=$(new_net_prefix)
done

# Subnet for the packets that are part of the test.
declare TEST_NET_PREFIX=$(new_net_prefix)
while ! docker network create \
  "--subnet=${TEST_NET_PREFIX}.0/${NET_MASK}" "${TEST_NET}"; do
  sleep 0.1
  declare TEST_NET_PREFIX=$(new_net_prefix)
done

docker pull "${IMAGE_TAG}"

# Create the DUT container and connect to network.
DUT=$(docker create ${RUNTIME_ARG} --privileged --rm \
  --stop-timeout ${TIMEOUT} -it ${IMAGE_TAG})
docker network connect "${CTRL_NET}" \
  --ip "${CTRL_NET_PREFIX}${DUT_NET_SUFFIX}" "${DUT}" \
  || (docker kill ${DUT}; docker rm ${DUT}; false)
docker network connect "${TEST_NET}" \
  --ip "${TEST_NET_PREFIX}${DUT_NET_SUFFIX}" "${DUT}" \
  || (docker kill ${DUT}; docker rm ${DUT}; false)
docker start "${DUT}"

# Create the test bench container and connect to network.
TESTBENCH=$(docker create --privileged --rm \
  --stop-timeout ${TIMEOUT} -it ${IMAGE_TAG})
docker network connect "${CTRL_NET}" \
  --ip "${CTRL_NET_PREFIX}${TESTBENCH_NET_SUFFIX}" "${TESTBENCH}" \
  || (docker kill ${TESTBENCH}; docker rm ${TESTBENCH}; false)
docker network connect "${TEST_NET}" \
  --ip "${TEST_NET_PREFIX}${TESTBENCH_NET_SUFFIX}" "${TESTBENCH}" \
  || (docker kill ${TESTBENCH}; docker rm ${TESTBENCH}; false)
docker start "${TESTBENCH}"

# Start the posix_server in the DUT.
declare -r DOCKER_POSIX_SERVER_BINARY="/$(basename ${POSIX_SERVER_BINARY})"
docker cp -L ${POSIX_SERVER_BINARY} "${DUT}:${DOCKER_POSIX_SERVER_BINARY}"

docker exec -t "${DUT}" \
  /bin/bash -c "${DOCKER_POSIX_SERVER_BINARY} \
  --ip ${CTRL_NET_PREFIX}${DUT_NET_SUFFIX} \
  --port ${CTRL_PORT}" &

# Because the Linux kernel receives the SYN-ACK but didn't send the SYN it will
# issue a RST. To prevent this IPtables can be used to filter those out.
docker exec "${TESTBENCH}" \
  iptables -A INPUT -i ${TEST_DEVICE} -j DROP

# Wait for the DUT server to come up.  Attempt to connect to it from the test
# bench every 100 milliseconds until success.
while ! docker exec "${TESTBENCH}" \
  nc -zv "${CTRL_NET_PREFIX}${DUT_NET_SUFFIX}" "${CTRL_PORT}"; do
  sleep 0.1
done

declare -r REMOTE_MAC=$(docker exec -t "${DUT}" ip link show \
  "${TEST_DEVICE}" | tail -1 | cut -d' ' -f6)
declare -r LOCAL_MAC=$(docker exec -t "${TESTBENCH}" ip link show \
  "${TEST_DEVICE}" | tail -1 | cut -d' ' -f6)

declare -r DOCKER_TESTBENCH_BINARY="/$(basename ${TESTBENCH_BINARY})"
docker cp -L "${TESTBENCH_BINARY}" "${TESTBENCH}:${DOCKER_TESTBENCH_BINARY}"

if [[ -z "${TSHARK-}" ]]; then
  # Run tcpdump in the test bench unbuffered, without dns resolution, just on
  # the interface with the test packets.
  docker exec -t "${TESTBENCH}" \
    tcpdump -S -vvv -U -n -i "${TEST_DEVICE}" net "${TEST_NET_PREFIX}/24" &
else
  # Run tshark in the test bench unbuffered, without dns resolution, just on the
  # interface with the test packets.
  docker exec -t "${TESTBENCH}" \
    tshark -V -l -n -i "${TEST_DEVICE}" \
    host "${TEST_NET_PREFIX}${TESTBENCH_NET_SUFFIX}" &
fi

# tcpdump and tshark take time to startup
sleep 3

# Start a packetimpact test on the test bench.  The packetimpact test sends and
# receives packets and also sends POSIX socket commands to the posix_server to
# be executed on the DUT.
docker exec -t "${TESTBENCH}" \
  /bin/bash -c "${DOCKER_TESTBENCH_BINARY} \
  --posix_server_ip=${CTRL_NET_PREFIX}${DUT_NET_SUFFIX} \
  --posix_server_port=${CTRL_PORT} \
  --remote_ipv4=${TEST_NET_PREFIX}${DUT_NET_SUFFIX} \
  --local_ipv4=${TEST_NET_PREFIX}${TESTBENCH_NET_SUFFIX} \
  --remote_mac=${REMOTE_MAC} \
  --local_mac=${LOCAL_MAC} \
  --device=${TEST_DEVICE}"

echo PASS: No errors.
