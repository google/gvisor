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
"""Redis-benchmark tool."""

import re

OPERATIONS = [
    "PING_INLINE",
    "PING_BULK",
    "SET",
    "GET",
    "INCR",
    "LPUSH",
    "RPUSH",
    "LPOP",
    "RPOP",
    "SADD",
    "HSET",
    "SPOP",
    "LRANGE_100",
    "LRANGE_300",
    "LRANGE_500",
    "LRANGE_600",
    "MSET",
]

METRICS = dict()

SAMPLE_DATA = """
"PING_INLINE","48661.80"
"PING_BULK","50301.81"
"SET","48923.68"
"GET","49382.71"
"INCR","49975.02"
"LPUSH","49875.31"
"RPUSH","50276.52"
"LPOP","50327.12"
"RPOP","50556.12"
"SADD","49504.95"
"HSET","49504.95"
"SPOP","50025.02"
"LPUSH (needed to benchmark LRANGE)","48875.86"
"LRANGE_100 (first 100 elements)","33955.86"
"LRANGE_300 (first 300 elements)","16550.81"
"LRANGE_500 (first 450 elements)","13653.74"
"LRANGE_600 (first 600 elements)","11219.57"
"MSET (10 keys)","44682.75"
"""


# pylint: disable=unused-argument
def sample(**kwargs) -> str:
  return SAMPLE_DATA


# Bind a metric for each operation noted above.
for op in OPERATIONS:

  def bind(metric):
    """Bind op to a new scope."""

    # pylint: disable=unused-argument
    def parse(data: str, **kwargs) -> float:
      """Operation throughput in requests/sec."""
      regex = r"\"" + metric + r"( .*)?\",\"(\d*.\d*)"
      res = re.compile(regex).search(data)
      if res:
        return float(res.group(2))
      return 0.0

    parse.__name__ = metric
    return parse

  METRICS[op] = bind(op)
