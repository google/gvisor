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

# Runs tcp_benchmark.sh over a matrix of round-trip times and loss
# probabilities, for netstack and for the Linux network stack. See README.md
# for documentation.
#
# usage: tcp_matrix.sh <count> <output-file> [tcp_benchmark.sh options]

if [[ $# -lt 2 || ! "$1" =~ ^[0-9]+$ ]]; then
  echo "usage: $0 <count> <output-file> [tcp_benchmark.sh options]" >&2
  exit 1
fi
count=$1
output=$2
shift 2

benchmark="$(dirname "$0")/tcp_benchmark.sh"

# Each entry selects the network stack of the sender and of the receiver. The
# netstack sender runs without GSO, with GSO that Linux segments, and with GSO
# that netstack segments. The last two entries are Linux on both sides, with
# the CPU usage of the sender and of the receiver.
stacks=(
  "--client"
  "--client --cubic"
  "--client --gso 65536"
  "--client --cubic --gso 65536"
  "--client --gso 65536 --swgso"
  "--client --cubic --gso 65536 --swgso"
  "--server"
  "--linux-client"
  ""
)

for ((i = 0; i < count; i++)); do
  for latency in 1 50 150; do
    # tcp_benchmark.sh applies half of the loss to each direction, so the data
    # packets have a loss of 0%, 0.01% and 0.1%.
    for loss in 0 0.02 0.2; do
      for stack in "${stacks[@]}"; do
        # Without segmentation offload, the network emulation drops and
        # queues single packets for Linux, as it does for netstack. Each entry
        # of stacks is a list of options, so the shell must split it.
        # shellcheck disable=SC2086
        if ! result=$("${benchmark}" --ideal --sack --disable-linux-gso \
          --latency "${latency}" --loss "${loss}" --rate 100 \
          ${stack} "$@"); then
          echo "tcp_benchmark.sh failed with: ${stack}" >&2
          exit 1
        fi
        echo "${result}" >> "${output}"
      done
    done
  done
done
