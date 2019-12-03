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
"""Density tests."""

import re
import types

from benchmarks import suites
from benchmarks.harness import container
from benchmarks.harness import machine
from benchmarks.suites import helpers


# pylint: disable=unused-argument
def memory_usage(value, **kwargs):
  """Returns the passed value."""
  return value


def density(target: machine.Machine,
            workload: str,
            count: int = 50,
            wait: float = 0,
            load_func: types.FunctionType = None,
            **kwargs):
  """Calculate the average memory usage per container.

  Args:
    target: A machine object.
    workload: The workload to run.
    count: The number of containers to start.
    wait: The time to wait after starting.
    load_func: Callback that is called after count images have been started on
      the given machine.
    **kwargs: Additional container options.

  Returns:
    The average usage in Kb per container.
  """
  count = int(count)

  # Drop all caches.
  helpers.drop_caches(target)
  before = target.read("/proc/meminfo")

  # Load the workload.
  image = target.pull(workload)

  with target.container(
      image=image, count=count, **kwargs).detach() as containers:
    # Call the optional load function callback if given.
    if load_func:
      load_func(target, containers)
    # Wait 'wait' time before taking a measurement.
    target.sleep(wait)

    # Drop caches again.
    helpers.drop_caches(target)
    after = target.read("/proc/meminfo")

  # Calculate the memory used.
  available_re = re.compile(r"MemAvailable:\s*(\d+)\skB\n")
  before_available = available_re.findall(before)
  after_available = available_re.findall(after)
  return 1024 * float(int(before_available[0]) -
                      int(after_available[0])) / float(count)


def load_redis(target: machine.Machine, containers: container.Container):
  """Use redis-benchmark "LPUSH" to load each container with 1G of data.

  Args:
    target: A machine object.
    containers: A set of containers.
  """
  target.pull("redisbenchmark")
  for name in containers.get_names():
    flags = "-d 10000 -t LPUSH"
    target.container(
        "redisbenchmark", links={
            name: name
        }).run(
            host=name, flags=flags)


@suites.benchmark(metrics=[memory_usage], machines=1)
def empty(target: machine.Machine, **kwargs) -> float:
  """Run trivial containers in a density test."""
  return density(target, workload="sleep", wait=1.0, **kwargs)


@suites.benchmark(metrics=[memory_usage], machines=1)
def node(target: machine.Machine, **kwargs) -> float:
  """Run node containers in a density test."""
  return density(target, workload="node", wait=3.0, **kwargs)


@suites.benchmark(metrics=[memory_usage], machines=1)
def ruby(target: machine.Machine, **kwargs) -> float:
  """Run ruby containers in a density test."""
  return density(target, workload="ruby", wait=3.0, **kwargs)


@suites.benchmark(metrics=[memory_usage], machines=1)
def redis(target: machine.Machine, **kwargs) -> float:
  """Run redis containers in a density test."""
  if "count" not in kwargs:
    kwargs["count"] = 5
  return density(
      target, workload="redis", wait=3.0, load_func=load_redis, **kwargs)
