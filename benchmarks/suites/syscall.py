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
"""Syscall microbenchmark."""

from benchmarks import suites
from benchmarks.harness import machine
from benchmarks.workloads.syscall import syscall_time_ns


@suites.benchmark(metrics=[syscall_time_ns], machines=1)
def syscall(target: machine.Machine, count: int = 1000000, **kwargs) -> str:
  """Runs the syscall workload and report the syscall time.

  Runs the syscall 'SYS_gettimeofday(0,0)' 'count' times and monitors time
  elapsed based on the runtime's MONOTONIC clock.

  Args:
    target: A machine object.
    count: The number of syscalls to execute.
    **kwargs: Additional container options.

  Returns:
    Container output.
  """
  image = target.pull("syscall")
  return target.container(image, **kwargs).run(count=count)
