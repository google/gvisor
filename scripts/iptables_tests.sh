#!/bin/bash

# Copyright 2018 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

source $(dirname $0)/common.sh

install_runsc_for_test iptables

# Build the docker image for the test.
run //test/iptables/runner --norun

# TODO(gvisor.dev/issue/170): Also test this on runsc once iptables are better
# supported
test //test/iptables:iptables_test "--test_arg=--runtime=runc" \
  "--test_arg=--image=bazel/test/iptables/runner:runner"
