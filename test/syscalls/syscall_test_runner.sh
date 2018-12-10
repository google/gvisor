#!/bin/bash

# Copyright 2018 Google LLC
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

# syscall_test_runner.sh is a simple wrapper around the go syscall test runner.
# It exists so that we can build the syscall test runner once, and use it for
# all syscall tests, rather than build it for each test run.

set -euf -o pipefail

# The syscall test runner binary and arguments have all been passed as arguments
# to this shell script.
exec "$@"
