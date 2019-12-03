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
"""ABSL build test."""

import sys

import pytest

from benchmarks.workloads import absl


def test_elapsed_time():
  """Test elapsed_time."""
  res = absl.elapsed_time(absl.sample())
  assert res == 81.861


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
