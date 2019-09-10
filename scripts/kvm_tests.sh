#!/bin/bash

# Copyright 2019 The gVisor Authors.
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

source $(dirname $0)/common.sh

# Ensure that KVM is loaded, and we can use it.
(lsmod | grep -E '^(kvm_intel|kvm_amd)') || sudo modprobe kvm
sudo chmod a+rw /dev/kvm

# Run all KVM platform tests (locally).
run_as_root //pkg/sentry/platform/kvm:kvm_test

# Install the KVM runtime and run all integration tests.
run_as_root //runsc install --experimental=true -- --debug --strace --log-packets --platform=kvm
sudo systemctl restart docker
test //test/image:image_test //test/e2e:integration_test
