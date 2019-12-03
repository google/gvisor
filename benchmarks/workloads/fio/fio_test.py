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
"""Parser tests."""

import sys

import pytest

from benchmarks.workloads import fio


def test_read_io_ops():
  """Test read ops parser."""
  assert fio.read_io_ops(fio.sample()) == 0.0


def test_write_io_ops():
  """Test write ops parser."""
  assert fio.write_io_ops(fio.sample()) == 438367.892977


def test_read_bandwidth():
  """Test read bandwidth parser."""
  assert fio.read_bandwidth(fio.sample()) == 0.0


def test_write_bandwith():
  """Test write bandwidth parser."""
  assert fio.write_bandwidth(fio.sample()) == 1753471 * 1024


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
