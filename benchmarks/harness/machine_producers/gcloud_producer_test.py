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
"""Tests GCloudProducer using mock data.

GCloudProducer produces machines using 'get_machines' and 'release_machines'
methods. The tests check recorded data (jsonified subprocess.CompletedProcess
objects) of the producer producing one and five machines.
"""
import os
import types

from benchmarks.harness.machine_producers import machine_producer
from benchmarks.harness.machine_producers import mock_producer

TEST_DIR = os.path.dirname(__file__)


def run_get_release(producer: machine_producer.MachineProducer,
                    num_machines: int,
                    validator: types.FunctionType = None):
  machines = producer.get_machines(num_machines)
  assert len(machines) == num_machines
  if validator:
    validator(machines=machines, cmd="uname -a", workload=None)
  producer.release_machines(machines)


def test_run_one():
  mock = mock_producer.MockReader(TEST_DIR + "get_one.json")
  producer = mock_producer.MockGCloudProducer(mock)
  run_get_release(producer, 1)


def test_run_five():
  mock = mock_producer.MockReader(TEST_DIR + "get_five.json")
  producer = mock_producer.MockGCloudProducer(mock)
  run_get_release(producer, 5)
