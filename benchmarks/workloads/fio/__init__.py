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
"""FIO benchmark tool."""

import json

SAMPLE_DATA = """
{
  "fio version" : "fio-3.1",
  "timestamp" : 1554837456,
  "timestamp_ms" : 1554837456621,
  "time" : "Tue Apr  9 19:17:36 2019",
  "jobs" : [
    {
      "jobname" : "test",
      "groupid" : 0,
      "error" : 0,
      "eta" : 2147483647,
      "elapsed" : 1,
      "job options" : {
        "name" : "test",
        "ioengine" : "sync",
        "size" : "1073741824",
        "filename" : "/disk/file.dat",
        "iodepth" : "4",
        "bs" : "4096",
        "rw" : "write"
      },
      "read" : {
        "io_bytes" : 0,
        "io_kbytes" : 0,
        "bw" : 0,
        "iops" : 0.000000,
        "runtime" : 0,
        "total_ios" : 0,
        "short_ios" : 0,
        "drop_ios" : 0,
        "slat_ns" : {
          "min" : 0,
          "max" : 0,
          "mean" : 0.000000,
          "stddev" : 0.000000
        },
        "clat_ns" : {
          "min" : 0,
          "max" : 0,
          "mean" : 0.000000,
          "stddev" : 0.000000,
          "percentile" : {
            "1.000000" : 0,
            "5.000000" : 0,
            "10.000000" : 0,
            "20.000000" : 0,
            "30.000000" : 0,
            "40.000000" : 0,
            "50.000000" : 0,
            "60.000000" : 0,
            "70.000000" : 0,
            "80.000000" : 0,
            "90.000000" : 0,
            "95.000000" : 0,
            "99.000000" : 0,
            "99.500000" : 0,
            "99.900000" : 0,
            "99.950000" : 0,
            "99.990000" : 0,
            "0.00" : 0,
            "0.00" : 0,
            "0.00" : 0
          }
        },
        "lat_ns" : {
          "min" : 0,
          "max" : 0,
          "mean" : 0.000000,
          "stddev" : 0.000000
        },
        "bw_min" : 0,
        "bw_max" : 0,
        "bw_agg" : 0.000000,
        "bw_mean" : 0.000000,
        "bw_dev" : 0.000000,
        "bw_samples" : 0,
        "iops_min" : 0,
        "iops_max" : 0,
        "iops_mean" : 0.000000,
        "iops_stddev" : 0.000000,
        "iops_samples" : 0
      },
      "write" : {
        "io_bytes" : 1073741824,
        "io_kbytes" : 1048576,
        "bw" : 1753471,
        "iops" : 438367.892977,
        "runtime" : 598,
        "total_ios" : 262144,
        "short_ios" : 0,
        "drop_ios" : 0,
        "slat_ns" : {
          "min" : 0,
          "max" : 0,
          "mean" : 0.000000,
          "stddev" : 0.000000
        },
        "clat_ns" : {
          "min" : 1693,
          "max" : 754733,
          "mean" : 2076.404373,
          "stddev" : 1724.195529,
          "percentile" : {
            "1.000000" : 1736,
            "5.000000" : 1752,
            "10.000000" : 1768,
            "20.000000" : 1784,
            "30.000000" : 1800,
            "40.000000" : 1800,
            "50.000000" : 1816,
            "60.000000" : 1816,
            "70.000000" : 1848,
            "80.000000" : 1928,
            "90.000000" : 2512,
            "95.000000" : 2992,
            "99.000000" : 6176,
            "99.500000" : 6304,
            "99.900000" : 11328,
            "99.950000" : 15168,
            "99.990000" : 17792,
            "0.00" : 0,
            "0.00" : 0,
            "0.00" : 0
          }
        },
        "lat_ns" : {
          "min" : 1731,
          "max" : 754770,
          "mean" : 2117.878979,
          "stddev" : 1730.290512
        },
        "bw_min" : 1731120,
        "bw_max" : 1731120,
        "bw_agg" : 98.725328,
        "bw_mean" : 1731120.000000,
        "bw_dev" : 0.000000,
        "bw_samples" : 1,
        "iops_min" : 432780,
        "iops_max" : 432780,
        "iops_mean" : 432780.000000,
        "iops_stddev" : 0.000000,
        "iops_samples" : 1
      },
      "trim" : {
        "io_bytes" : 0,
        "io_kbytes" : 0,
        "bw" : 0,
        "iops" : 0.000000,
        "runtime" : 0,
        "total_ios" : 0,
        "short_ios" : 0,
        "drop_ios" : 0,
        "slat_ns" : {
          "min" : 0,
          "max" : 0,
          "mean" : 0.000000,
          "stddev" : 0.000000
        },
        "clat_ns" : {
          "min" : 0,
          "max" : 0,
          "mean" : 0.000000,
          "stddev" : 0.000000,
          "percentile" : {
            "1.000000" : 0,
            "5.000000" : 0,
            "10.000000" : 0,
            "20.000000" : 0,
            "30.000000" : 0,
            "40.000000" : 0,
            "50.000000" : 0,
            "60.000000" : 0,
            "70.000000" : 0,
            "80.000000" : 0,
            "90.000000" : 0,
            "95.000000" : 0,
            "99.000000" : 0,
            "99.500000" : 0,
            "99.900000" : 0,
            "99.950000" : 0,
            "99.990000" : 0,
            "0.00" : 0,
            "0.00" : 0,
            "0.00" : 0
          }
        },
        "lat_ns" : {
          "min" : 0,
          "max" : 0,
          "mean" : 0.000000,
          "stddev" : 0.000000
        },
        "bw_min" : 0,
        "bw_max" : 0,
        "bw_agg" : 0.000000,
        "bw_mean" : 0.000000,
        "bw_dev" : 0.000000,
        "bw_samples" : 0,
        "iops_min" : 0,
        "iops_max" : 0,
        "iops_mean" : 0.000000,
        "iops_stddev" : 0.000000,
        "iops_samples" : 0
      },
      "usr_cpu" : 17.922948,
      "sys_cpu" : 81.574539,
      "ctx" : 3,
      "majf" : 0,
      "minf" : 10,
      "iodepth_level" : {
        "1" : 100.000000,
        "2" : 0.000000,
        "4" : 0.000000,
        "8" : 0.000000,
        "16" : 0.000000,
        "32" : 0.000000,
        ">=64" : 0.000000
      },
      "latency_ns" : {
        "2" : 0.000000,
        "4" : 0.000000,
        "10" : 0.000000,
        "20" : 0.000000,
        "50" : 0.000000,
        "100" : 0.000000,
        "250" : 0.000000,
        "500" : 0.000000,
        "750" : 0.000000,
        "1000" : 0.000000
      },
      "latency_us" : {
        "2" : 82.737350,
        "4" : 12.605286,
        "10" : 4.543686,
        "20" : 0.107956,
        "50" : 0.010000,
        "100" : 0.000000,
        "250" : 0.000000,
        "500" : 0.000000,
        "750" : 0.000000,
        "1000" : 0.010000
      },
      "latency_ms" : {
        "2" : 0.000000,
        "4" : 0.000000,
        "10" : 0.000000,
        "20" : 0.000000,
        "50" : 0.000000,
        "100" : 0.000000,
        "250" : 0.000000,
        "500" : 0.000000,
        "750" : 0.000000,
        "1000" : 0.000000,
        "2000" : 0.000000,
        ">=2000" : 0.000000
      },
      "latency_depth" : 4,
      "latency_target" : 0,
      "latency_percentile" : 100.000000,
      "latency_window" : 0
    }
  ],
  "disk_util" : [
    {
      "name" : "dm-1",
      "read_ios" : 0,
      "write_ios" : 3,
      "read_merges" : 0,
      "write_merges" : 0,
      "read_ticks" : 0,
      "write_ticks" : 0,
      "in_queue" : 0,
      "util" : 0.000000,
      "aggr_read_ios" : 0,
      "aggr_write_ios" : 3,
      "aggr_read_merges" : 0,
      "aggr_write_merge" : 0,
      "aggr_read_ticks" : 0,
      "aggr_write_ticks" : 0,
      "aggr_in_queue" : 0,
      "aggr_util" : 0.000000
    },
    {
      "name" : "dm-0",
      "read_ios" : 0,
      "write_ios" : 3,
      "read_merges" : 0,
      "write_merges" : 0,
      "read_ticks" : 0,
      "write_ticks" : 0,
      "in_queue" : 0,
      "util" : 0.000000,
      "aggr_read_ios" : 0,
      "aggr_write_ios" : 3,
      "aggr_read_merges" : 0,
      "aggr_write_merge" : 0,
      "aggr_read_ticks" : 0,
      "aggr_write_ticks" : 2,
      "aggr_in_queue" : 0,
      "aggr_util" : 0.000000
    },
    {
      "name" : "nvme0n1",
      "read_ios" : 0,
      "write_ios" : 3,
      "read_merges" : 0,
      "write_merges" : 0,
      "read_ticks" : 0,
      "write_ticks" : 2,
      "in_queue" : 0,
      "util" : 0.000000
    }
  ]
}
"""


# pylint: disable=unused-argument
def sample(**kwargs) -> str:
  return SAMPLE_DATA


# pylint: disable=unused-argument
def read_bandwidth(data: str, **kwargs) -> int:
  """File I/O bandwidth."""
  return json.loads(data)["jobs"][0]["read"]["bw"] * 1024


# pylint: disable=unused-argument
def write_bandwidth(data: str, **kwargs) -> int:
  """File I/O bandwidth."""
  return json.loads(data)["jobs"][0]["write"]["bw"] * 1024


# pylint: disable=unused-argument
def read_io_ops(data: str, **kwargs) -> float:
  """File I/O operations per second."""
  return float(json.loads(data)["jobs"][0]["read"]["iops"])


# pylint: disable=unused-argument
def write_io_ops(data: str, **kwargs) -> float:
  """File I/O operations per second."""
  return float(json.loads(data)["jobs"][0]["write"]["iops"])


# Change function names so we just print "bandwidth" and "io_ops".
read_bandwidth.__name__ = "bandwidth"
write_bandwidth.__name__ = "bandwidth"
read_io_ops.__name__ = "io_ops"
write_io_ops.__name__ = "io_ops"
