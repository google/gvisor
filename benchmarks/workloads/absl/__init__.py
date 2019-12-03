# python3
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
"""ABSL build benchmark."""

import re

SAMPLE_BAZEL_OUTPUT = """Extracting Bazel installation...
Starting local Bazel server and connecting to it...
Loading:
Loading: 0 packages loaded
Loading: 0 packages loaded
    currently loading: absl/algorithm ... (11 packages)
Analyzing: 241 targets (16 packages loaded, 0 targets configured)
Analyzing: 241 targets (21 packages loaded, 617 targets configured)
Analyzing: 241 targets (27 packages loaded, 687 targets configured)
Analyzing: 241 targets (32 packages loaded, 1105 targets configured)
Analyzing: 241 targets (32 packages loaded, 1294 targets configured)
Analyzing: 241 targets (35 packages loaded, 1575 targets configured)
Analyzing: 241 targets (35 packages loaded, 1575 targets configured)
Analyzing: 241 targets (36 packages loaded, 1603 targets configured)
Analyzing: 241 targets (36 packages loaded, 1603 targets configured)
INFO: Analyzed 241 targets (37 packages loaded, 1864 targets configured).
INFO: Found 241 targets...
[0 / 5] [Prepa] BazelWorkspaceStatusAction stable-status.txt
[16 / 50] [Analy] Compiling absl/base/dynamic_annotations.cc ... (20 actions, 10 running)
[60 / 77] Compiling external/com_google_googletest/googletest/src/gtest.cc; 5s processwrapper-sandbox ... (12 actions, 11 running)
[158 / 174] Compiling absl/container/internal/raw_hash_set_test.cc; 2s processwrapper-sandbox ... (12 actions, 11 running)
[278 / 302] Compiling absl/container/internal/raw_hash_set_test.cc; 6s processwrapper-sandbox ... (12 actions, 11 running)
[384 / 406] Compiling absl/container/internal/raw_hash_set_test.cc; 10s processwrapper-sandbox ... (12 actions, 11 running)
[581 / 604] Compiling absl/container/flat_hash_set_test.cc; 11s processwrapper-sandbox ... (12 actions, 11 running)
[722 / 745] Compiling absl/container/node_hash_set_test.cc; 9s processwrapper-sandbox ... (12 actions, 11 running)
[846 / 867] Compiling absl/hash/hash_test.cc; 11s processwrapper-sandbox ... (12 actions, 11 running)
INFO: From Compiling absl/debugging/symbolize_test.cc:
/tmp/cclCVipU.s: Assembler messages:
/tmp/cclCVipU.s:1662: Warning: ignoring changed section attributes for .text
[999 / 1,022] Compiling absl/hash/hash_test.cc; 19s processwrapper-sandbox ... (12 actions, 11 running)
[1,082 / 1,084] Compiling absl/container/flat_hash_map_test.cc; 7s processwrapper-sandbox
INFO: Elapsed time: 81.861s, Critical Path: 23.81s
INFO: 515 processes: 515 processwrapper-sandbox.
INFO: Build completed successfully, 1084 total actions
INFO: Build completed successfully, 1084 total actions"""


def sample():
  return SAMPLE_BAZEL_OUTPUT


# pylint: disable=unused-argument
def elapsed_time(data: str, **kwargs) -> float:
  """Returns the elapsed time for running an absl build."""
  return float(re.compile(r"Elapsed time: (\d*.?\d*)s").search(data).group(1))
