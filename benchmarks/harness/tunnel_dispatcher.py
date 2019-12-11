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
"""Tunnel handles setting up connections to remote machines.

Tunnel dispatcher is a wrapper around the connection from a local UNIX socket
and a remote UNIX socket via SSH with port forwarding. This is done to
initialize the pythonic dockerpy client to run containers on the remote host by
connecting to /var/run/docker.sock (where Docker is listening). Tunnel
dispatcher sets up the local UNIX socket and calls the `ssh` command as a
subprocess, and holds a reference to that subprocess. It manages clean-up on
exit as best it can by killing the ssh subprocess and deleting the local UNIX
socket,stored in /tmp for easy cleanup in most systems if this fails.

  Typical usage example:

  t = Tunnel(name, **kwargs)
  t.connect()
  client = t.get_docker_client() #
  client.containers.run("ubuntu", "echo hello world")

"""

import os
import tempfile
import time

import docker
import pexpect

SSH_TUNNEL_COMMAND = """ssh
    -o GlobalKnownHostsFile=/dev/null
    -o UserKnownHostsFile=/dev/null
    -o StrictHostKeyChecking=no
    -o IdentitiesOnly=yes
    -nNT -L {filename}:/var/run/docker.sock
    -i {key_path}
    {username}@{hostname}"""


class Tunnel(object):
  """The tunnel object represents the tunnel via ssh.

  This connects a local unix domain socket with a remote socket.

  Attributes:
      _filename: a temporary name of the UNIX socket prefixed by the name
        argument.
      _hostname: the IP or resolvable hostname of the remote host.
      _username: the username of the ssh_key used to run ssh.
      _key_path: path to a valid key.
      _key_password: optional password to the ssh key in _key_path
      _process: holds reference to the ssh subprocess created.

    Returns:
      The new minimum port.

    Raises:
      ConnectionError: If no available port is found.
  """

  def __init__(self,
               name: str,
               hostname: str,
               username: str,
               key_path: str,
               key_password: str = "",
               **kwargs):
    self._filename = tempfile.NamedTemporaryFile(prefix=name).name
    self._hostname = hostname
    self._username = username
    self._key_path = key_path
    self._key_password = key_password
    self._kwargs = kwargs
    self._process = None

  def connect(self):
    """Connects the SSH tunnel and stores the subprocess reference in _process."""
    cmd = SSH_TUNNEL_COMMAND.format(
        filename=self._filename,
        key_path=self._key_path,
        username=self._username,
        hostname=self._hostname)
    self._process = pexpect.spawn(cmd, timeout=10)

    # If given a password, assume we'll be asked for it.
    if self._key_password:
      self._process.expect(["Enter passphrase for key .*: "])
      self._process.sendline(self._key_password)

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
    """Returns a docker client for this Tunnel."""
    return docker.DockerClient(base_url="unix:/" + self._filename)

  def __del__(self):
    """Closes the ssh connection process and deletes the socket file."""
    if self._process:
      self._process.close()
    if os.path.exists(self._filename):
      os.remove(self._filename)
