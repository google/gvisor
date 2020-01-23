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
# Device-Under-Test (DUT) and one for the test runner.  Each is attached with
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

declare -r LONGOPTS="dut_platform:,stub:,test_runner_py:,runtime:"

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
    --stub)
      declare -r STUB="$2"
      shift 2
      ;;
    --test_runner_py)
      declare -r TEST_RUNNER_PY="$2"
      shift 2
      ;;
    --runtime)
      # Not readonly because there might be multiple --runtime arguments and we
      # want to use just the last one.  Only used if --dut_platform is
      # "netstack".
      declare RUNTIME="$2"
      shift 2
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
if [[ ! -f "${STUB-}" ]]; then
  echo "FAIL: Bad or missing --stub: ${STUB-}"
  exit 2
fi
if [[ ! -f "${TEST_RUNNER_PY-}" ]]; then
  echo "FAIL: Bad or missing --test_runner_py: ${TEST_RUNNER_PY-}"
  exit 2
fi

# Variables specific to the control network and interface start with CTRL_.
# Variables specific to the test network and interface start with TEST_.
# Variables specific to the DUT start with DUT_.
# Variables specific to the test runner start with TEST_RUNNER_.
# Use random numbers so that test networks don't collide.
declare -r CTRL_NET="ctrl_net-${RANDOM}${RANDOM}"
declare -r TEST_NET="test_net-${RANDOM}${RANDOM}"
# On both DUT and test runner, testing packets are on the eth2 interface.
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
# Last bits of the test runner's IP address.
declare -r TEST_RUNNER_NET_SUFFIX=".20"
declare -r TIMEOUT="60"
# TODO(eyalsoha): Use an image from gco.io.
declare -r IMAGE_TAG="eyal0/gvisor:latest"

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

# Subnet for control packets between test runner and DUT.
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

# Create the test runner container and connect to network.
TEST_RUNNER=$(docker create --privileged --rm \
  --stop-timeout ${TIMEOUT} -it ${IMAGE_TAG})
docker network connect "${CTRL_NET}" \
  --ip "${CTRL_NET_PREFIX}${TEST_RUNNER_NET_SUFFIX}" "${TEST_RUNNER}" \
  || (docker kill ${TEST_RUNNER}; docker rm ${REST_RUNNER}; false)
docker network connect "${TEST_NET}" \
  --ip "${TEST_NET_PREFIX}${TEST_RUNNER_NET_SUFFIX}" "${TEST_RUNNER}" \
  || (docker kill ${TEST_RUNNER}; docker rm ${REST_RUNNER}; false)
docker start "${TEST_RUNNER}"

# Run tcpdump in the test runner unbuffered, without dns resolution, just on the
# interface with the test packets.
docker exec -t ${TEST_RUNNER} tcpdump -U -n -i "${TEST_DEVICE}" &

docker cp -L "${STUB}" "${DUT}:$(basename ${STUB})"
docker exec -t "${DUT}" g++ stub.cc -l jsoncpp -o stub

# Start a packetimpact stub on the DUT.  The stub receives POSIX commands and
# returns responses.
docker exec "${DUT}" ls -l "/$(basename ${STUB})"
docker exec -d "${DUT}" "/stub" \
  --ip="${CTRL_NET_PREFIX}${DUT_NET_SUFFIX}" \
  --port="${CTRL_PORT}"

# Because the Linux kernel receives the SYN-ACK but didn't send the SYN it will
# issue a RST. To prevent this IPtables can be used to filter those out.
docker exec "${TEST_RUNNER}" \
  iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# Wait for the packetdrill server on the test runner to come.  Attempt to
# connect to it from the test runner every 100 milliseconds until success.
while ! docker exec "${TEST_RUNNER}" \
  nc -zv -u "${CTRL_NET_PREFIX}${DUT_NET_SUFFIX}" "${CTRL_PORT}"; do
  sleep 0.1
done

# Copy the packetimpact tests to the test_runner.
declare -a docker_scripts
for script in $scripts; do
  docker cp -L "${script}" "${TEST_RUNNER}:$(basename ${script})"
  docker_scripts+=("/$(basename ${script})")
done

docker cp -L "${TEST_RUNNER_PY}" "${TEST_RUNNER}:$(basename ${TEST_RUNNER_PY})"

# Start a packetimpact test on the test runner.  The packetimpact test sends and
# receives packets and also sends POSIX socket commands to the stub to be
# executed on the DUT.
for docker_script in "${docker_scripts[@]}"; do
  docker exec -t "${TEST_RUNNER}" \
    /usr/bin/python3 "${docker_script}" \
    --stub_ip="${CTRL_NET_PREFIX}${DUT_NET_SUFFIX}" \
    --stub_port="${CTRL_PORT}" \
    --local_ip="${TEST_NET_PREFIX}${TEST_RUNNER_NET_SUFFIX}" \
    --remote_ip="${TEST_NET_PREFIX}${DUT_NET_SUFFIX}" \
    --device="${TEST_DEVICE}"
done

echo PASS: No errors.
