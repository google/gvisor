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
"""Producers based on yaml files."""

import os
import threading
from typing import Dict
from typing import List

import yaml

from benchmarks.harness import machine
from benchmarks.harness.machine_producers import machine_producer


class YamlMachineProducer(machine_producer.MachineProducer):
  """Loads machines from a yaml file."""

  def __init__(self, path: str):
    self.machines = build_machines(path)
    self.max_machines = len(self.machines)
    self.machine_condition = threading.Condition()

  def get_machines(self, num_machines: int) -> List[machine.Machine]:
    if num_machines > self.max_machines:
      raise ValueError(
          "Insufficient Ammount of Machines. {ask} asked for and have {max_num} max."
          .format(ask=num_machines, max_num=self.max_machines))

    with self.machine_condition:
      while not self._enough_machines(num_machines):
        self.machine_condition.wait(timeout=1)
      return [self.machines.pop(0) for _ in range(num_machines)]

  def release_machines(self, machine_list: List[machine.Machine]):
    with self.machine_condition:
      while machine_list:
        next_machine = machine_list.pop()
        self.machines.append(next_machine)
      self.machine_condition.notify()

  def _enough_machines(self, ask: int):
    return ask <= len(self.machines)


def build_machines(path: str, num_machines: str = -1) -> List[machine.Machine]:
  """Builds machine objects defined by the yaml file "path".

  Args:
    path: The path to a yaml file which defines machines.
    num_machines: Optional limit on how many machine objects to build.

  Returns:
    Machine objects in a list.

    If num_machines is set, len(machines) <= num_machines.
  """
  data = parse_yaml(path)
  machines = []
  for key, value in data.items():
    if len(machines) == num_machines:
      return machines
    if isinstance(value, dict):
      machines.append(machine.RemoteMachine(key, **value))
    else:
      machines.append(machine.LocalMachine(key))
  return machines


def parse_yaml(path: str) -> Dict[str, Dict[str, str]]:
  """Parse the yaml file pointed by path.

  Args:
    path: The path to yaml file.

  Returns:
    The contents of the yaml file as a dictionary.
  """
  data = get_file_contents(path)
  return yaml.load(data, Loader=yaml.Loader)


def get_file_contents(path: str) -> str:
  """Dumps the file contents to a string and returns them.

  Args:
    path: The path to dump.

  Returns:
    The file contents as a string.
  """
  if not os.path.isabs(path):
    path = os.path.abspath(path)
  with open(path) as input_file:
    return input_file.read()
