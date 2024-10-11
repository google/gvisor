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

# Create a new veth pair in the current namespace and change the MTU.
ip link add name test_veth01 type veth peer name test_veth02
ip link set test_veth01 mtu 3000
ip link show test_veth01 | grep -E "mtu 3000"
ip link del name test_veth01
# Check that test_veth02 has been destroyed.
if ! wait_for ! ip link show test_veth02; then
  fail "test_veth02 hasn't been destroyed"
  exit 1
fi

# Create a new veth pair in the current namespace and rename the link.
ip link add name test_veth01 type veth peer name test_veth02
ip link set test_veth01 name test_veth03
ip link show test_veth03
ip link del name test_veth03
# Check that test_veth02 has been destroyed.
if ! wait_for ! ip link show test_veth02; then
  fail "test_veth02 hasn't been destroyed"
  exit 1
fi

# Change the hardware address of a new veth device.
ip link add name test_veth01 type veth peer name test_veth02
ip link set dev test_veth01 address 1a:2a:3a:4a:5a:6a
ip link show test_veth01 | grep "1a:2a:3a:4a:5a:6a"
ip link del name test_veth01
# Check that test_veth02 has been destroyed.
if ! wait_for ! ip link show test_veth02; then
  fail "test_veth02 hasn't been destroyed"
  exit 1
fi
