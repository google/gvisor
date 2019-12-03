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
"""Parser test."""

import sys

import pytest

from benchmarks.workloads import ab


def test_transfer_rate_parser():
  """Test transfer rate parser."""
  res = ab.transfer_rate(ab.sample())
  assert res == 210.84


def test_latency_parser():
  """Test latency parser."""
  res = ab.latency(ab.sample())
  assert res == 2


def test_requests_per_second():
  """Test requests per second parser."""
  res = ab.requests_per_second(ab.sample())
  assert res == 556.44


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
