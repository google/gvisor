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
"""SSHConnection handles the details of SSH connections."""

import os
import warnings

import paramiko

from benchmarks import harness

# Get rid of paramiko Cryptography Warnings.
warnings.filterwarnings(action="ignore", module=".*paramiko.*")


def send_one_file(client: paramiko.SSHClient, path: str, remote_dir: str):
  """Sends a single file via an SSH client.

  Args:
    client: The existing SSH client.
    path: The local path.
    remote_dir: The remote directory.
  """
  filename = path.split("/").pop()
  client.exec_command("mkdir -p " + remote_dir)
  with client.open_sftp() as ftp_client:
    ftp_client.put(path, os.path.join(remote_dir, filename))


class SSHConnection:
  """SSH connection to a remote machine."""

  def __init__(self, name: str, hostname: str, key_path: str, username: str,
               **kwargs):
    """Sets up a paramiko ssh connection to the given hostname."""
    self._name = name  # Unused.
    self._hostname = hostname
    self._username = username
    self._key_path = key_path  # RSA Key path
    self._kwargs = kwargs
    # SSHConnection wraps paramiko. paramiko supports RSA, ECDSA, and Ed25519
    # keys, and we've chosen to only suport and require RSA keys. paramiko
    # supports RSA keys that begin with '----BEGIN RSAKEY----'.
    # https://stackoverflow.com/questions/53600581/ssh-key-generated-by-ssh-keygen-is-not-recognized-by-paramiko
    self.rsa_key = self._rsa()
    self.run("true")  # Validate.

  def _client(self) -> paramiko.SSHClient:
    """Returns a connected SSH client."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=self._hostname,
        port=22,
        username=self._username,
        pkey=self.rsa_key,
        allow_agent=False,
        look_for_keys=False)
    return client

  def _rsa(self):
    if "key_password" in self._kwargs:
      password = self._kwargs["key_password"]
    else:
      password = None
    rsa = paramiko.RSAKey.from_private_key_file(self._key_path, password)
    return rsa

  def run(self, cmd: str) -> (str, str):
    """Runs a command via ssh.

    Args:
      cmd: The shell command to run.

    Returns:
      The contents of stdout and stderr.
    """
    with self._client() as client:
      _, stdout, stderr = client.exec_command(command=cmd)
      stdout.channel.recv_exit_status()
      stdout = stdout.read().decode("utf-8")
      stderr = stderr.read().decode("utf-8")
    return stdout, stderr

  def send_workload(self, name: str) -> str:
    """Sends a workload to the remote machine.

    Args:
      name: The workload name.

    Returns:
      The remote path.
    """
    with self._client() as client:
      for dirpath, _, filenames in os.walk(
          harness.LOCAL_WORKLOADS_PATH.format(name)):
        for filename in filenames:
          send_one_file(client, os.path.join(dirpath, filename),
                        harness.REMOTE_WORKLOADS_PATH.format(name))
    return harness.REMOTE_WORKLOADS_PATH.format(name)
