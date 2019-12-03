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
"""Tunnel handles setting up connections to remote machines."""

import os
import tempfile
import time

import docker
import pexpect

SSH_TUNNEL_COMMAND = """ssh
 -o GlobalKnownHostsFile=/dev/null
 -o UserKnownHostsFile=/dev/null
 -o StrictHostKeyChecking=no
 -nNT -L {filename}:/var/run/docker.sock
 -i {key_path}
 {username}@{hostname}"""


class Tunnel:
  """The tunnel object represents the tunnel via ssh.

  This connects a local unix domain socket with a remote socket.
  """

  def __init__(self, name, hostname: str, username: str, key_path: str,
               **kwargs):
    self._filename = tempfile.NamedTemporaryFile(prefix=name).name
    self._hostname = hostname
    self._username = username
    self._key_path = key_path
    self._kwargs = kwargs
    self._process = None

  def connect(self):
    """Connects the SSH tunnel."""
    cmd = SSH_TUNNEL_COMMAND.format(
        filename=self._filename,
        key_path=self._key_path,
        username=self._username,
        hostname=self._hostname)
    self._process = pexpect.spawn(cmd, timeout=10)

    # If given a password, assume we'll be asked for it.
    if "key_password" in self._kwargs:
      self._process.expect(["Enter passphrase for key .*: "])
      self._process.sendline(self._kwargs["key_password"])

    while True:
      # Wait for the tunnel to appear.
      if self._process.exitstatus is not None:
        raise ConnectionError("Error in setting up ssh tunnel")
      if os.path.exists(self._filename):
        return
      time.sleep(0.1)

  def path(self):
    """Return the socket file."""
    return self._filename

  def get_docker_client(self):
    """Returns a docker client for this Tunne0l."""
    return docker.DockerClient(base_url="unix:/" + self._filename)

  def __del__(self):
    """Closes the ssh connection process and deletes the socket file."""
    if self._process:
      self._process.close()
    if os.path.exists(self._filename):
      os.remove(self._filename)
