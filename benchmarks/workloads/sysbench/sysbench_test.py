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

from benchmarks.workloads import sysbench


def test_sysbench_parser():
  """Test the basic parser."""
  assert sysbench.cpu_events_per_second(sysbench.sample("cpu")) == 9093.38
  assert sysbench.memory_ops_per_second(sysbench.sample("memory")) == 9597428.64
  assert sysbench.mutex_time(sysbench.sample("mutex"), 1, 1,
                             100000000.0) == 3.754
  assert sysbench.mutex_deviation(sysbench.sample("mutex")) == 0.03
  assert sysbench.mutex_latency(sysbench.sample("mutex")) == 3754.03


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
