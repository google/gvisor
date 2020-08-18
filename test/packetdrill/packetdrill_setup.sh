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

# This script runs both within the sentry context and natively. It should tweak
# TCP parameters to match expectations found in the script files.
sysctl -q net.ipv4.tcp_sack=1
sysctl -q net.ipv4.tcp_rmem="4096 2097152 $((8*1024*1024))"
sysctl -q net.ipv4.tcp_wmem="4096 2097152 $((8*1024*1024))"

# There may be errors from the above, but they will show up in the test logs and
# we always want to proceed from this point. It's possible that values were
# already set correctly and the nodes were not available in the namespace.
exit 0
