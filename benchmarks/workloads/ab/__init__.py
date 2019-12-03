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
"""Apachebench tool."""

import re

SAMPLE_DATA = """This is ApacheBench, Version 2.3 <$Revision: 1826891 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 10.10.10.10 (be patient).....done


Server Software:        Apache/2.4.38
Server Hostname:        10.10.10.10
Server Port:            80

Document Path:          /latin10k.txt
Document Length:        210 bytes

Concurrency Level:      1
Time taken for tests:   0.180 seconds
Complete requests:      100
Failed requests:        0
Non-2xx responses:      100
Total transferred:      38800 bytes
HTML transferred:       21000 bytes
Requests per second:    556.44 [#/sec] (mean)
Time per request:       1.797 [ms] (mean)
Time per request:       1.797 [ms] (mean, across all concurrent requests)
Transfer rate:          210.84 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    0   0.2      0       2
Processing:     1    2   1.0      1       8
Waiting:        1    1   1.0      1       7
Total:          1    2   1.2      1      10

Percentage of the requests served within a certain time (ms)
  50%      1
  66%      2
  75%      2
  80%      2
  90%      2
  95%      3
  98%      7
  99%     10
 100%     10 (longest request)"""


# pylint: disable=unused-argument
def sample(**kwargs) -> str:
  return SAMPLE_DATA


# pylint: disable=unused-argument
def transfer_rate(data: str, **kwargs) -> float:
  """Mean transfer rate in Kbytes/sec."""
  regex = r"Transfer rate:\s+(\d+\.?\d+?)\s+\[Kbytes/sec\]\s+received"
  return float(re.compile(regex).search(data).group(1))


# pylint: disable=unused-argument
def latency(data: str, **kwargs) -> float:
  """Mean latency in milliseconds."""
  regex = r"Total:\s+\d+\s+(\d+)\s+(\d+\.?\d+?)\s+\d+\s+\d+\s"
  res = re.compile(regex).search(data)
  return float(res.group(1))


# pylint: disable=unused-argument
def requests_per_second(data: str, **kwargs) -> float:
  """Requests per second."""
  regex = r"Requests per second:\s+(\d+\.?\d+?)\s+"
  res = re.compile(regex).search(data)
  return float(res.group(1))
