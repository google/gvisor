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

from benchmarks.workloads import redisbenchmark

RESULTS = {
    "PING_INLINE": 48661.80,
    "PING_BULK": 50301.81,
    "SET": 48923.68,
    "GET": 49382.71,
    "INCR": 49975.02,
    "LPUSH": 49875.31,
    "RPUSH": 50276.52,
    "LPOP": 50327.12,
    "RPOP": 50556.12,
    "SADD": 49504.95,
    "HSET": 49504.95,
    "SPOP": 50025.02,
    "LRANGE_100": 33955.86,
    "LRANGE_300": 16550.81,
    "LRANGE_500": 13653.74,
    "LRANGE_600": 11219.57,
    "MSET": 44682.75
}


def test_metrics():
  """Test all metrics."""
  for (metric, func) in redisbenchmark.METRICS.items():
    res = func(redisbenchmark.sample())
    assert float(res) == RESULTS[metric]


if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))
