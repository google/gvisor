# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Python binding for gVisor sandbox.

This module provides a Python API for creating gVisor sandboxes and executing
commands inside them.
"""

import json
import os
import random
import shutil
import subprocess
import tempfile
from typing import Optional, Tuple


class SandboxError(Exception):
  """Base exception for Sandbox operations."""


class Sandbox:
  """Represents a running gVisor sandbox."""

  def __init__(
      self,
      runtime_dir: Optional[str] = None,
      sandbox_id: Optional[str] = None,
      enable_networking: bool = True,
  ):
    """Initializes and starts a new sandbox.

    Args:
      runtime_dir: Custom runtime directory where bundle and state files are
        written. If not set, a temporary directory is created.
      sandbox_id: Specific sandbox ID. If not set, a unique ID is generated
        automatically.
      enable_networking: Whether networking is enabled inside the sandbox.

    Raises:
      SandboxError: If sandbox creation fails.
    """
    self._enable_networking = enable_networking
    self._runtime_dir = ""
    self._owns_runtime_dir = False
    self._id = ""
    self._state_dir = ""
    self._bundle_dir = ""
    self._closed = False
    self._runsc_path = self._find_runsc()

    if runtime_dir is None:
      try:
        self._runtime_dir = tempfile.mkdtemp(prefix="gvisor-sandbox-")
      except OSError as e:
        raise SandboxError(f"failed to create runtime directory: {e}") from e
      self._owns_runtime_dir = True
    else:
      self._runtime_dir = runtime_dir
      self._owns_runtime_dir = False

    self._id = sandbox_id or self._generate_id()

    try:
      if os.geteuid() != 0 and self._enable_networking:
        raise SandboxError("enabling networking requires running as root")

      self._state_dir = os.path.join(self._runtime_dir, "state")
      try:
        os.makedirs(self._state_dir, mode=0o700, exist_ok=True)
      except OSError as e:
        raise SandboxError(
            f"failed to create sandbox state directory: {e}"
        ) from e

      # Verify permissions (mode might be different if directory already existed).
      try:
        stat_info = os.stat(self._state_dir)
        if (stat_info.st_mode & 0o777) != 0o700:
          os.chmod(self._state_dir, 0o700)
      except OSError as e:
        raise SandboxError(
            "sandbox state directory has incorrect permissions and failed to"
            f" chmod: {e}"
        ) from e

      self._bundle_dir = self._create_bundle()

      # Launch the sandbox in detached mode.
      args = ["--root", self._state_dir]
      if os.geteuid() != 0:
        args.append("--ignore-cgroups")
      if not self._enable_networking:
        args.append("--network=none")
      args.extend(["run", "--bundle", self._bundle_dir, "--detach", self._id])

      # We must use a file for stderr because runsc run with --detach spawns a
      # grandchild process. If we use pipes (e.g. capture_output=True), Python's
      # subprocess.run will hang waiting for the pipes to close. Writing to a
      # file avoids this hang while still allowing us to capture errors.
      stderr_path = os.path.join(self._runtime_dir, "runsc-stderr.log")
      try:
        with open(stderr_path, "w+b") as stderr_file:
          subprocess.run(
              [self._runsc_path] + args,
              check=True,
              stdout=subprocess.DEVNULL,
              stderr=stderr_file,
              timeout=30,
          )
      except subprocess.TimeoutExpired as e:
        raise SandboxError("sandbox creation timed out (runsc run hung)") from e
      except subprocess.CalledProcessError as e:
        stderr_content = ""
        if os.path.exists(stderr_path):
          try:
            with open(stderr_path, "r", errors="replace") as f:
              stderr_content = f.read()
          except OSError:
            pass
        raise SandboxError(
            f"failed to create sandbox via subprocess: exit code {e.returncode},"
            f" stderr: {stderr_content}"
        ) from e
    except Exception:
      self.close()
      raise

  def __enter__(self) -> "Sandbox":
    return self

  def __exit__(self, exc_type, exc_val, exc_tb):
    self.close()

  @property
  def id(self) -> str:
    """Returns the sandbox ID."""
    return self._id

  @property
  def bundle_dir(self) -> str:
    """Returns the path to the OCI bundle directory."""
    return self._bundle_dir

  def _generate_id(self) -> str:
    return f"{random.getrandbits(128):032x}"

  def _find_runsc(self) -> str:
    if "RUNSC_PATH" in os.environ:
      return os.environ["RUNSC_PATH"]
    path = shutil.which("runsc")
    if path is not None:
      return path
    raise SandboxError("runsc binary is not found")

  def _create_bundle(self) -> str:
    """Creates the OCI bundle directory and config.json.

    Returns:
      The path to the created bundle directory.

    Raises:
      SandboxError: If bundle creation fails.
    """
    bundle_dir = os.path.join(self._runtime_dir, self._id)
    rootfs_dir = os.path.join(bundle_dir, "rootfs")
    try:
      os.makedirs(rootfs_dir, mode=0o755, exist_ok=True)
    except OSError as e:
      raise SandboxError(f"failed to create bundle directories: {e}") from e

    namespaces = [
        {"type": "pid"},
        {"type": "mount"},
        {"type": "uts"},
        {"type": "ipc"},
    ]
    if os.geteuid() != 0:
      namespaces.append({"type": "user"})
    if self._enable_networking:
      namespaces.append({"type": "network"})

    mounts = [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
    ]

    for p in ["/bin", "/usr", "/lib", "/lib64", "/etc/alternatives"]:
      if os.path.exists(p):
        opts = ["rbind", "ro", "nosuid", "nodev"]
        if p == "/etc/alternatives":
          opts = ["rbind", "ro"]
        mounts.append({
            "destination": p,
            "type": "bind",
            "source": p,
            "options": opts,
        })

    linux = {
        "namespaces": namespaces,
    }
    if os.geteuid() != 0:
      linux["uidMappings"] = [
          {"containerID": 0, "hostID": os.geteuid(), "size": 1}
      ]
      linux["gidMappings"] = [
          {"containerID": 0, "hostID": os.getegid(), "size": 1}
      ]

    spec = {
        "ociVersion": "1.0.0",
        "root": {
            "path": "rootfs",
            "readonly": True,
        },
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": ["sleep", "infinity"],
            "cwd": "/",
            "env": ["PATH=/bin:/usr/bin:/usr/local/bin"],
        },
        "mounts": mounts,
        "linux": linux,
    }

    config_path = os.path.join(bundle_dir, "config.json")
    try:
      with open(config_path, "w") as f:
        json.dump(spec, f, indent=2)
    except OSError as e:
      raise SandboxError(f"failed to create config.json: {e}") from e

    return bundle_dir

  def exec(
      self, cmd: str, *args: str, timeout: Optional[float] = None
  ) -> Tuple[str, str]:
    """Runs the given command inside the running sandbox.

    Args:
      cmd: The command to run.
      *args: Arguments to the command.
      timeout: Timeout in seconds.

    Returns:
      A tuple of (stdout, stderr) strings.

    Raises:
      SandboxError: If the command execution fails or times out.
    """
    runsc_args = ["--root", self._state_dir, "exec", self._id, cmd] + list(args)
    try:
      result = subprocess.run(
          [self._runsc_path] + runsc_args,
          capture_output=True,
          text=True,
          check=True,
          timeout=timeout,
      )
      return result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
      raise SandboxError(f"exec timed out after {timeout} seconds") from e
    except subprocess.CalledProcessError as e:
      raise SandboxError(f"exec failed: {e.stderr}") from e

  def close(self):
    """Kills the sandbox processes and cleans up directories."""
    if self._closed:
      return
    self._closed = True

    if self._state_dir:
      kill_args = ["--root", self._state_dir, "kill", self._id, "SIGKILL"]
      subprocess.run(
          [self._runsc_path] + kill_args, capture_output=True, check=False
      )

      delete_args = ["--root", self._state_dir, "delete", "--force", self._id]
      delete_result = subprocess.run(
          [self._runsc_path] + delete_args, capture_output=True, check=False
      )
      if delete_result.returncode != 0:
        # We might want to log this, but we continue cleanup anyway.
        pass

    if self._bundle_dir and os.path.exists(self._bundle_dir):
      try:
        shutil.rmtree(self._bundle_dir)
      except OSError:
        pass

    if self._owns_runtime_dir and os.path.exists(self._runtime_dir):
      try:
        shutil.rmtree(self._runtime_dir)
      except OSError:
        pass
