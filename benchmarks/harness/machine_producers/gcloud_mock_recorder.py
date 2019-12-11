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
"""A recorder and replay for testing the GCloudProducer.

MockPrinter and MockReader handle printing and reading mock data for the
purposes of testing. MockPrinter is passed to GCloudProducer objects. The user
can then run scenarios and record them for playback in tests later.

MockReader is passed to MockGcloudProducer objects and handles reading the
previously recorded mock data.

It is left to the user to check if data printed is properly redacted for their
own use. The intended usecase for this class is data coming from gcloud
commands, which will contain public IPs and other instance data.

The data format is json and printed/read from the ./test_data directory. The
data is the output of subprocess.CompletedProcess objects in json format.

  Typical usage example:

  recorder = MockPrinter()
  producer = GCloudProducer(args, recorder)
  machines = producer.get_machines(1)
  with open("my_file.json") as fd:
    recorder.write_out(fd)

  reader = MockReader(filename)
  producer = MockGcloudProducer(args, mock)
  machines = producer.get_machines(1)
  assert len(machines) == 1
"""

import io
import json
import subprocess


class MockPrinter(object):
  """Handles printing Mock data for MockGcloudProducer.

  Attributes:
    _records: list of json object records for printing
  """

  def __init__(self):
    self._records = []

  def record(self, entry: subprocess.CompletedProcess):
    """Records data and strips out ip addresses."""

    record = {
        "args": entry.args,
        "stdout": entry.stdout.decode("utf-8"),
        "returncode": str(entry.returncode)
    }
    self._records.append(record)

  def write_out(self, fd: io.FileIO):
    """Prints out the data into the given filepath."""
    fd.write(json.dumps(self._records, indent=4))


class MockReader(object):
  """Handles reading Mock data for MockGcloudProducer.

  Attributes:
    _records: List[json] records read from the passed in file.
  """

  def __init__(self, filepath: str):
    with open(filepath, "rb") as file:
      self._records = json.loads(file.read())
      self._i = 0

  def __iter__(self):
    return self

  def __next__(self, args) -> subprocess.CompletedProcess:
    """Returns the next record as a CompletedProcess."""
    if self._i < len(self._records):
      record = self._records[self._i]
      stdout = record["stdout"].encode("ascii")
      returncode = int(record["returncode"])
      return subprocess.CompletedProcess(
          args=args, returncode=returncode, stdout=stdout, stderr=b"")
    raise StopIteration()
