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

# Create a new veth pair in the current namespace.
ip link add name test_veth01 type veth peer name test_veth02
ip a
ip a | grep test_veth01
ip a | grep test_veth02
ip link del name test_veth01
ip a
# Check that test_veth02 has been destroyed.
if ! wait_for ! ip link show test_veth02; then
  fail "test_veth02 hasn't been destroyed"
  exit 1
fi

# Create new veth pair where devices are in two namespaces.
ip netns add test
ip link add test_veth01 type veth peer name test_veth02 netns test
ip link show test_veth01
ip netns exec test ip link show test_veth02
ip netns del test
if ! wait_for ! ip link show test_veth01; then
  fail "test_veth01 hasn't been destroyed"
fi

# Create new veth pair and move one end in another namespace.
ip netns add test
ip link add test_veth01 type veth peer name test_veth02
ip link set dev test_veth02 netns test
ip link show test_veth01
ip netns exec test ip link show test_veth02
# Check that test_veth02 will be destroyed after changing netns.
ip link del test_veth01
if ! wait_for ! ip netns exec test ip link show test_veth02; then
  fail "test_veth02 hasn't been destroyed"
fi
ip netns del test
