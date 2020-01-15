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
"""Abstract types."""

import threading
from typing import List

from benchmarks.harness import machine


class MachineProducer:
  """Abstract Machine producer."""

  def get_machines(self, num_machines: int) -> List[machine.Machine]:
    """Returns the requested number of machines."""
    raise NotImplementedError

  def release_machines(self, machine_list: List[machine.Machine]):
    """Releases the given set of machines."""
    raise NotImplementedError


class LocalMachineProducer(MachineProducer):
  """Produces Local Machines."""

  def __init__(self, limit: int):
    self.limit_sem = threading.Semaphore(value=limit)

  def get_machines(self, num_machines: int) -> List[machine.Machine]:
    """Returns the request number of MockMachines."""

    self.limit_sem.acquire()
    return [machine.LocalMachine("local") for _ in range(num_machines)]

  def release_machines(self, machine_list: List[machine.MockMachine]):
    """No-op."""
    if not machine_list:
      raise ValueError("Cannot release an empty list!")
    self.limit_sem.release()
    machine_list.clear()
