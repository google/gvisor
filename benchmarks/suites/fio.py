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
"""File I/O tests."""

import os

from benchmarks import suites
from benchmarks.harness import machine
from benchmarks.suites import helpers
from benchmarks.workloads import fio


# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
def run_fio(target: machine.Machine,
            test: str,
            ioengine: str = "sync",
            size: int = 1024 * 1024 * 1024,
            iodepth: int = 4,
            blocksize: int = 1024 * 1024,
            time: int = -1,
            mount_dir: str = "",
            filename: str = "file.dat",
            tmpfs: bool = False,
            ramp_time: int = 0,
            **kwargs) -> str:
  """FIO benchmarks.

  For more on fio see:
    https://media.readthedocs.org/pdf/fio/latest/fio.pdf

  Args:
    target: A machine object.
    test: The test to run (read, write, randread, randwrite, etc.)
    ioengine: The engine for I/O.
    size: The size of the generated file in bytes (if an integer) or 5g, 16k,
      etc.
    iodepth: The I/O for certain engines.
    blocksize: The blocksize for reads and writes in bytes (if an integer) or
      4k, etc.
    time: If test is time based, how long to run in seconds.
    mount_dir: The absolute path on the host to mount a bind mount.
    filename: The name of the file to creat inside container. For a path of
      /dir/dir/file, the script setup a volume like 'docker run -v
        mount_dir:/dir/dir fio' and fio will create (and delete) the file
          /dir/dir/file. If tmpfs is set, this /dir/dir will be a tmpfs.
    tmpfs: If true, mount on tmpfs.
    ramp_time: The time to run before recording statistics
    **kwargs: Additional container options.

  Returns:
    The output of fio as a string.
  """
  # Pull the image before dropping caches.
  image = target.pull("fio")

  if not mount_dir:
    stdout, _ = target.run("pwd")
    mount_dir = stdout.rstrip()

  # Setup the volumes.
  volumes = {mount_dir: {"bind": "/disk", "mode": "rw"}} if not tmpfs else None
  tmpfs = {"/disk": ""} if tmpfs else None

  # Construct a file in the volume.
  filepath = os.path.join("/disk", filename)

  # If we are running a read test, us fio to write a file and then flush file
  # data from memory.
  if "read" in test:
    target.container(
        image, volumes=volumes, tmpfs=tmpfs, **kwargs).run(
            test="write",
            ioengine="sync",
            size=size,
            iodepth=iodepth,
            blocksize=blocksize,
            path=filepath)
    helpers.drop_caches(target)

  # Run the test.
  time_str = "--time_base --runtime={time}".format(
      time=time) if int(time) > 0 else ""
  res = target.container(
      image, volumes=volumes, tmpfs=tmpfs, **kwargs).run(
          test=test,
          ioengine=ioengine,
          size=size,
          iodepth=iodepth,
          blocksize=blocksize,
          time=time_str,
          path=filepath,
          ramp_time=ramp_time)

  target.run(
      "rm {path}".format(path=os.path.join(mount_dir.rstrip(), filename)))

  return res


@suites.benchmark(metrics=[fio.read_bandwidth, fio.read_io_ops], machines=1)
def read(*args, **kwargs):
  """Read test.

  Args:
    *args: None.
    **kwargs: Additional container options.

  Returns:
    The output of fio.
  """
  return run_fio(*args, test="read", **kwargs)


@suites.benchmark(metrics=[fio.read_bandwidth, fio.read_io_ops], machines=1)
def randread(*args, **kwargs):
  """Random read test.

  Args:
    *args: None.
    **kwargs: Additional container options.

  Returns:
    The output of fio.
  """
  return run_fio(*args, test="randread", **kwargs)


@suites.benchmark(metrics=[fio.write_bandwidth, fio.write_io_ops], machines=1)
def write(*args, **kwargs):
  """Write test.

  Args:
    *args: None.
    **kwargs: Additional container options.

  Returns:
    The output of fio.
  """
  return run_fio(*args, test="write", **kwargs)


@suites.benchmark(metrics=[fio.write_bandwidth, fio.write_io_ops], machines=1)
def randwrite(*args, **kwargs):
  """Random write test.

  Args:
    *args: None.
    **kwargs: Additional container options.

  Returns:
    The output of fio.
  """
  return run_fio(*args, test="randwrite", **kwargs)
