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
"""Start-up benchmarks."""

from benchmarks import suites
from benchmarks.harness import machine
from benchmarks.suites import helpers


# pylint: disable=unused-argument
def startup_time_ms(value, **kwargs):
  """Returns average startup time per container in milliseconds.

  Args:
    value: The floating point time in seconds.
    **kwargs: Ignored.

  Returns:
    The time given in milliseconds.
  """
  return value * 1000


def startup(target: machine.Machine,
            workload: str,
            count: int = 5,
            port: int = 0,
            **kwargs):
  """Time the startup of some workload.

  Args:
    target: A machine object.
    workload: The workload to run.
    count: Number of containers to start.
    port: The port to check for liveness, if provided.
    **kwargs: Additional container options.

  Returns:
    The mean start-up time in seconds.
  """
  # Load before timing.
  image = target.pull(workload)
  netcat = target.pull("netcat")
  count = int(count)
  port = int(port)

  with helpers.Timer() as timer:
    for _ in range(count):
      if not port:
        # Run the container synchronously.
        target.container(image, **kwargs).run()
      else:
        # Run a detached container until httpd available.
        with target.container(image, port=port, **kwargs).detach() as server:
          (server_host, server_port) = server.address()
          target.container(netcat).run(host=server_host, port=server_port)
    return timer.elapsed() / float(count)


@suites.benchmark(metrics=[startup_time_ms], machines=1)
def empty(target: machine.Machine, **kwargs) -> float:
  """Time the startup of a trivial container.

  Args:
    target: A machine object.
    **kwargs: Additional startup options.

  Returns:
    The time to run the container.
  """
  return startup(target, workload="true", **kwargs)


@suites.benchmark(metrics=[startup_time_ms], machines=1)
def node(target: machine.Machine, **kwargs) -> float:
  """Time the startup of the node container.

  Args:
    target: A machine object.
    **kwargs: Additional statup options.

  Returns:
    The time to run the container.
  """
  return startup(target, workload="node", port=8080, **kwargs)


@suites.benchmark(metrics=[startup_time_ms], machines=1)
def ruby(target: machine.Machine, **kwargs) -> float:
  """Time the startup of the ruby container.

  Args:
    target: A machine object.
    **kwargs: Additional startup options.

  Returns:
    The time to run the container.
  """
  return startup(target, workload="ruby", port=3000, **kwargs)
