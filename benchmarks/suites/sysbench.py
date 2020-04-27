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
"""Sysbench-based benchmarks."""

from benchmarks import suites
from benchmarks.harness import machine
from benchmarks.workloads import sysbench


def run_sysbench(target: machine.Machine,
                 test: str = "cpu",
                 threads: int = 8,
                 time: int = 5,
                 options: str = "",
                 **kwargs) -> str:
  """Run sysbench container with arguments.

  Args:
    target: A machine object.
    test: Relevant sysbench test to run (e.g. cpu, memory).
    threads: The number of threads to use for tests.
    time: The time to run tests.
    options: Additional sysbench options.
    **kwargs: Additional container options.

  Returns:
    The output of the command as a string.
  """
  image = target.pull("sysbench")
  return target.container(image, **kwargs).run(
      test=test, threads=threads, time=time, options=options)


@suites.benchmark(metrics=[sysbench.cpu_events_per_second], machines=1)
def cpu(target: machine.Machine, max_prime: int = 5000, **kwargs) -> str:
  """Run sysbench CPU test.

  Additional arguments can be provided for sysbench.

  Args:
    target: A machine object.
    max_prime: The maximum prime number to search.
    **kwargs:
      - threads: The number of threads to use for tests.
      - time: The time to run tests.
      - options: Additional sysbench options. See sysbench tool:
        https://github.com/akopytov/sysbench

  Returns:
    Sysbench output.
  """
  options = kwargs.pop("options", "")
  options += " --cpu-max-prime={}".format(max_prime)
  return run_sysbench(target, test="cpu", options=options, **kwargs)


@suites.benchmark(metrics=[sysbench.memory_ops_per_second], machines=1)
def memory(target: machine.Machine, **kwargs) -> str:
  """Run sysbench memory test.

  Additional arguments can be provided per sysbench.

  Args:
    target: A machine object.
    **kwargs:
        - threads: The number of threads to use for tests.
        - time: The time to run tests.
        - options: Additional sysbench options. See sysbench tool:
          https://github.com/akopytov/sysbench

  Returns:
    Sysbench output.
  """
  return run_sysbench(target, test="memory", **kwargs)


@suites.benchmark(
    metrics=[
        sysbench.mutex_time, sysbench.mutex_latency, sysbench.mutex_deviation
    ],
    machines=1)
def mutex(target: machine.Machine,
          locks: int = 4,
          count: int = 10000000,
          threads: int = 8,
          **kwargs) -> str:
  """Run sysbench mutex test.

  Additional arguments can be provided per sysbench.

  Args:
    target: A machine object.
    locks: The number of locks to use.
    count: The number of mutexes.
    threads: The number of threads to use for tests.
    **kwargs:
        - time: The time to run tests.
        - options: Additional sysbench options. See sysbench tool:
          https://github.com/akopytov/sysbench

  Returns:
    Sysbench output.
  """
  options = kwargs.pop("options", "")
  options += " --mutex-loops=1 --mutex-locks={} --mutex-num={}".format(
      count, locks)
  return run_sysbench(
      target, test="mutex", options=options, threads=threads, **kwargs)
