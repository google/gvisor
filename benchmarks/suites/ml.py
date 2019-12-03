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
"""Machine Learning tests."""

from benchmarks import suites
from benchmarks.harness import machine
from benchmarks.suites import startup
from benchmarks.workloads import tensorflow


@suites.benchmark(metrics=[tensorflow.run_time], machines=1)
def train(target: machine.Machine, **kwargs):
  """Run the tensorflow benchmark and return the runtime in seconds of workload.

  Args:
    target: A machine object.
    **kwargs: Additional container options.

  Returns:
    The total runtime.
  """
  return startup.startup(target, workload="tensorflow", count=1, **kwargs)
