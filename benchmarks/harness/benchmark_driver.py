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
"""Main driver for benchmarks."""

import copy
import statistics
import threading
import types

from benchmarks import suites
from benchmarks.harness.machine_producers import machine_producer


# pylint: disable=too-many-instance-attributes
class BenchmarkDriver:
  """Allocates machines and invokes a benchmark method."""

  def __init__(self,
               producer: machine_producer.MachineProducer,
               method: types.FunctionType,
               runs: int = 1,
               **kwargs):

    self._producer = producer
    self._method = method
    self._kwargs = copy.deepcopy(kwargs)
    self._threads = []
    self.lock = threading.RLock()
    self._runs = runs
    self._metric_results = {}

  def start(self):
    """Starts a benchmark thread."""
    for _ in range(self._runs):
      thread = threading.Thread(target=self._run_method)
      thread.start()
      self._threads.append(thread)

  def join(self):
    """Joins the thread."""
    # pylint: disable=expression-not-assigned
    [t.join() for t in self._threads]

  def _run_method(self):
    """Runs all benchmarks."""
    machines = self._producer.get_machines(
        suites.benchmark_machines(self._method))
    try:
      result = self._method(*machines, **self._kwargs)
      for name, res in result:
        with self.lock:
          if name in self._metric_results:
            self._metric_results[name].append(res)
          else:
            self._metric_results[name] = [res]
    finally:
      # Always release.
      self._producer.release_machines(machines)

  def median(self):
    """Returns the median result, after join is finished."""
    for key, value in self._metric_results.items():
      yield key, [statistics.median(value)]

  def all(self):
    """Returns all results."""
    for key, value in self._metric_results.items():
      yield key, value

  def meanstd(self):
    """Returns all results."""
    for key, value in self._metric_results.items():
      mean = statistics.mean(value)
      yield key, [mean, statistics.stdev(value, xbar=mean)]
