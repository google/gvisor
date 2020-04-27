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
"""Media processing benchmarks."""

from benchmarks import suites
from benchmarks.harness import machine
from benchmarks.suites import helpers
from benchmarks.workloads import ffmpeg


@suites.benchmark(metrics=[ffmpeg.run_time], machines=1)
def transcode(target: machine.Machine, **kwargs) -> float:
  """Runs a video transcoding workload and times it.

  Args:
    target: A machine object.
    **kwargs: Additional container options.

  Returns:
    Total workload runtime.
  """
  # Load before timing.
  image = target.pull("ffmpeg")

  # Drop caches.
  helpers.drop_caches(target)

  # Time startup + transcoding.
  with helpers.Timer() as timer:
    target.container(image, **kwargs).run()
    return timer.elapsed()
