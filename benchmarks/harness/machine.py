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
"""Machine abstraction. This is the primary API for benchmarks."""

import logging
import re
import subprocess
import time
from typing import Tuple

import docker

from benchmarks import harness
from benchmarks.harness import container
from benchmarks.harness import machine_mocks
from benchmarks.harness import ssh_connection
from benchmarks.harness import tunnel_dispatcher


class Machine:
  """The machine object is the primary object for benchmarks.

  Machine objects are passed to each metric function call and benchmarks use
  machines to access real connections to those machines.
  """

  def run(self, cmd: str) -> Tuple[str, str]:
    """Convenience method for running a bash command on a machine object.

    Some machines may point to the local machine, and thus, do not have ssh
    connections. Run runs a command either local or over ssh and returns the
    output stdout and stderr as strings.

    Args:
      cmd: The command to run as a string.

    Returns:
      The command output.
    """
    raise NotImplementedError

  def read(self, path: str) -> str:
    """Reads the contents of some file.

    This will be mocked.

    Args:
      path: The path to the file to be read.

    Returns:
      The file contents.
    """
    raise NotImplementedError

  def pull(self, workload: str) -> str:
    """Send the given workload to the machine, build and tag it.

    All images must be defined by the workloads directory.

    Args:
      workload: The workload name.

    Returns:
      The workload tag.
    """
    raise NotImplementedError

  def container(self, image: str, **kwargs) -> container.Container:
    """Returns a container object.

    Args:
      image: The pulled image tag.
      **kwargs: Additional container options.

    Returns:
        :return: a container.Container object.
    """
    raise NotImplementedError

  def sleep(self, amount: float):
    """Sleeps the given amount of time."""
    raise NotImplementedError


class MockMachine(Machine):
  """A mocked machine."""

  def run(self, cmd: str) -> Tuple[str, str]:
    return "", ""

  def read(self, path: str) -> str:
    return machine_mocks.Readfile(path)

  def pull(self, workload: str) -> str:
    return workload  # Workload is the tag.

  def container(self, image: str, **kwargs) -> container.Container:
    return container.MockContainer(image)

  def sleep(self, amount: float):
    pass


def get_address(machine: Machine) -> str:
  """Return a machine's default address."""
  default_route, _ = machine.run("ip route get 8.8.8.8")
  return re.search(" src ([0-9.]+) ", default_route).group(1)


class LocalMachine(Machine):
  """The local machine."""

  def __init__(self, name):
    self._name = name
    self._docker_client = docker.from_env()

  def __str__(self):
    return self._name

  def run(self, cmd: str) -> Tuple[str, str]:
    process = subprocess.Popen(
        cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode("utf-8"), stderr.decode("utf-8")

  def read(self, path: str) -> str:
    # Read the exact path locally.
    return open(path, "r").read()

  def pull(self, workload: str) -> str:
    # Run the docker build command locally.
    logging.info("Building %s@%s locally...", workload, self._name)
    self.run("docker build --tag={} {}".format(
        workload, harness.LOCAL_WORKLOADS_PATH.format(workload)))
    return workload  # Workload is the tag.

  def container(self, image: str, **kwargs) -> container.Container:
    # Return a local docker container directly.
    return container.DockerContainer(self._docker_client, get_address(self),
                                     image, **kwargs)

  def sleep(self, amount: float):
    time.sleep(amount)


class RemoteMachine(Machine):
  """Remote machine accessible via an SSH connection."""

  def __init__(self, name, **kwargs):
    self._name = name
    self._ssh_connection = ssh_connection.SSHConnection(name, **kwargs)
    self._tunnel = tunnel_dispatcher.Tunnel(name, **kwargs)
    self._tunnel.connect()
    self._docker_client = self._tunnel.get_docker_client()

  def __str__(self):
    return self._name

  def run(self, cmd: str) -> Tuple[str, str]:
    return self._ssh_connection.run(cmd)

  def read(self, path: str) -> str:
    # Just cat remotely.
    stdout, stderr = self._ssh_connection.run("cat '{}'".format(path))
    return stdout + stderr

  def pull(self, workload: str) -> str:
    # Push to the remote machine and build.
    logging.info("Building %s@%s remotely...", workload, self._name)
    remote_path = self._ssh_connection.send_workload(workload)
    self.run("docker build --tag={} {}".format(workload, remote_path))
    return workload  # Workload is the tag.

  def container(self, image: str, **kwargs) -> container.Container:
    # Return a remote docker container.
    return container.DockerContainer(self._docker_client, get_address(self),
                                     image, **kwargs)

  def sleep(self, amount: float):
    time.sleep(amount)
