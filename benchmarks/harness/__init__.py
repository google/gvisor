# python3
# Copyright 2019 The gVisor Authors.
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
"""Core benchmark utilities."""

import getpass
import os
import subprocess
import tempfile

# LOCAL_WORKLOADS_PATH defines the path to use for local workloads. This is a
# format string that accepts a single string parameter.
LOCAL_WORKLOADS_PATH = os.path.dirname(__file__) + "/../workloads/{}/tar.tar"

# REMOTE_WORKLOADS_PATH defines the path to use for storing the workloads on the
# remote host. This is a format string that accepts a single string parameter.
REMOTE_WORKLOADS_PATH = "workloads/{}"

# INSTALLER_ROOT is the set of files that needs to be copied.
INSTALLER_ARCHIVE = os.readlink(os.path.join(
    os.path.dirname(__file__), "installers.tar"))

# SSH_KEY_DIR holds SSH_PRIVATE_KEY for this run. bm-tools paramiko requires
# keys generated with the '-t rsa -m PEM' options from ssh-keygen. This is
# abstracted away from the user.
SSH_KEY_DIR = tempfile.TemporaryDirectory()
SSH_PRIVATE_KEY = "key"

# DEFAULT_USER is the default user running this script.
DEFAULT_USER = getpass.getuser()

# DEFAULT_USER_HOME is the home directory of the user running the script.
DEFAULT_USER_HOME = os.environ["HOME"] if "HOME" in os.environ else ""

# Default directory to remotely installer "installer" targets.
REMOTE_INSTALLERS_PATH = "installers"


def make_key():
  """Wraps a valid ssh key in a temporary directory."""
  path = os.path.join(SSH_KEY_DIR.name, SSH_PRIVATE_KEY)
  if not os.path.exists(path):
    cmd = "ssh-keygen -t rsa -m PEM -b 4096 -f {key} -q -N".format(
        key=path).split(" ")
    cmd.append("")
    subprocess.run(cmd, check=True)
  return path


def delete_key():
  """Deletes temporary directory containing private key."""
  SSH_KEY_DIR.cleanup()
