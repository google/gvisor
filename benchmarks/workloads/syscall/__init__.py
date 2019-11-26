# python3
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Simple syscall test."""

import re

SAMPLE_DATA = "Called getpid syscall 1000000 times: 1117 ms, 500 ns each."


# pylint: disable=unused-argument
def sample(**kwargs) -> str:
  return SAMPLE_DATA


# pylint: disable=unused-argument
def syscall_time_ns(data: str, **kwargs) -> int:
  """Returns average system call time."""
  return float(re.compile(r"(\d+)\sns each.").search(data).group(1))
