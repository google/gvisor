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
"""Producers of mocks."""

from typing import List

from benchmarks.harness import machine
from benchmarks.harness.machine_producers import machine_producer


class MockMachineProducer(machine_producer.MachineProducer):
  """Produces MockMachine objects."""

  def get_machines(self, num_machines: int) -> List[machine.MockMachine]:
    """Returns the request number of MockMachines."""
    return [machine.MockMachine() for i in range(num_machines)]

  def release_machines(self, machine_list: List[machine.MockMachine]):
    """No-op."""
    return
