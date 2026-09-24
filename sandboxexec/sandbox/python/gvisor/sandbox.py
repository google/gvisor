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

import dataclasses
import enum
import json
import os
import posixpath
import random
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


class Error(Exception):
  """Base exception for Sandbox operations."""


class MountType(str, enum.Enum):
  """Type of mount point inside the sandbox."""

  BIND = "bind"
  TMPFS = "tmpfs"
  PROC = "proc"


class NetworkMode(str, enum.Enum):
  """Network isolation mode for the sandbox."""

  NONE = "none"
  HOST = "host"
  SANDBOX = "sandbox"


@dataclasses.dataclass(frozen=True)
class Mount:
  """Represents a mount configuration inside the sandbox.

  Attributes:
    destination: Destination path inside the sandbox.
    source: Source path on the host (for bind mounts) or mount source
      identifier.
    type: Mount type ('bind', 'tmpfs', 'proc').
    readonly: Whether the mount is read-only (applies to bind mounts).
  """

  destination: str
  source: Optional[str] = None
  type: Union[MountType, str] = MountType.BIND
  readonly: bool = False

  @classmethod
  def bind(
      cls, source: str, destination: str, readonly: bool = False
  ) -> "Mount":
    """Creates a host bind mount."""
    return cls(
        destination=destination,
        source=source,
        type=MountType.BIND,
        readonly=readonly,
    )

  @classmethod
  def tmpfs(cls, destination: str) -> "Mount":
    """Creates an in-memory tmpfs mount."""
    return cls(
        destination=destination,
        source="tmpfs",
        type=MountType.TMPFS,
        readonly=False,
    )

  @classmethod
  def proc(cls, destination: str) -> "Mount":
    """Creates an isolated procfs mount."""
    return cls(
        destination=destination,
        source="proc",
        type=MountType.PROC,
        readonly=False,
    )


def _normalize_env(
    env: Optional[Union[List[str], Dict[str, str]]],
    base_env: Optional[Dict[str, str]] = None,
) -> List[str]:
  """Normalizes environment variables into a list of 'KEY=VALUE' strings.

  Args:
    env: A list of 'KEY=VALUE' strings or a dict mapping keys to values.
    base_env: Optional default environment dictionary to merge over.

  Returns:
    A deduplicated list of 'KEY=VALUE' strings.

  Raises:
    ValueError: If a list entry is missing '=' or a dict key contains '='.
    TypeError: If env is not a list, tuple, or dict.
  """
  merged = dict(base_env) if base_env else {}
  if not env:
    return [f"{k}={v}" for k, v in merged.items()]

  if isinstance(env, dict):
    for k, v in env.items():
      if "=" in str(k):
        raise ValueError(f"Environment variable key cannot contain '=': {k!r}")
      merged[str(k)] = str(v)
  elif isinstance(env, (list, tuple)):
    for item in env:
      if not isinstance(item, str) or "=" not in item:
        raise ValueError(
            f"Invalid environment variable format, expected KEY=VALUE: {item!r}"
        )
      k, _, v = item.partition("=")
      merged[k] = v
  else:
    raise TypeError(
        f"env must be a list of 'KEY=VALUE' strings or a dict, got {type(env)}"
    )

  return [f"{k}={v}" for k, v in merged.items()]


def _normalize_working_dir(
    working_dir: Optional[str], param_name: str = "working_dir"
) -> str:
  """Normalizes and validates working directory into an absolute POSIX path.

  Relative paths are resolved and normalized relative to the container root
  ('/').

  Args:
    working_dir: The working directory path.
    param_name: Parameter name for error messages (e.g. 'working_dir' or 'cwd').

  Returns:
    The normalized absolute POSIX working directory path.

  Raises:
    TypeError: If working_dir is not a string.
    ValueError: If working_dir is empty or whitespace.
  """
  if working_dir is None:
    return "/"
  if not isinstance(working_dir, str):
    raise TypeError(f"{param_name} must be a str, got {type(working_dir)}")
  if not working_dir.strip():
    err_msg = (
        "working directory cannot be empty"
        if param_name == "working_dir"
        else f"{param_name} cannot be empty"
    )
    raise ValueError(err_msg)
  return posixpath.normpath(posixpath.join("/", working_dir))


def _normalize_mounts(
    mounts: Optional[Sequence[Union[Mount, Dict[str, Any]]]],
) -> List[Mount]:
  """Normalizes and validates mount configurations into a list of Mount objects.

  Args:
    mounts: A sequence of Mount objects or dictionaries specifying mounts.

  Returns:
    A list of normalized Mount objects.

  Raises:
    TypeError: If mounts is not a sequence, or an item is neither a Mount nor
      a dict.
    ValueError: If a mount dictionary contains unrecognized keys, destination
      is missing or empty, bind mount source is empty, or mount type is invalid.
  """
  if not mounts:
    return []

  if not isinstance(mounts, (list, tuple)):
    raise TypeError(
        "mounts must be a list or tuple of Mount objects or dicts, got"
        f" {type(mounts)}"
    )

  normalized = []
  for item in mounts:
    if isinstance(item, Mount):
      m_dest = item.destination
      m_source = item.source
      m_type = item.type
      m_readonly = item.readonly
    elif isinstance(item, dict):
      allowed_keys = {"destination", "source", "type", "readonly"}
      extra_keys = set(item.keys()) - allowed_keys
      if extra_keys:
        raise ValueError(
            f"Unrecognized keys in mount dict: {sorted(extra_keys)}"
        )
      if "destination" not in item:
        raise ValueError(f"Mount dictionary missing 'destination': {item!r}")
      m_dest = item["destination"]
      m_source = item.get("source")
      m_type = item.get("type", MountType.BIND)
      m_readonly = item.get("readonly", False)
    else:
      raise TypeError(
          f"Mount item must be a Mount instance or dict, got {type(item)}"
      )

    if not isinstance(m_dest, str) or not m_dest.strip():
      raise ValueError(f"Mount destination cannot be empty: {m_dest!r}")

    clean_dest = posixpath.normpath(posixpath.join("/", m_dest))

    if isinstance(m_type, MountType):
      type_str = m_type.value
    elif isinstance(m_type, str):
      type_str = m_type.lower()
      if type_str not in (
          MountType.BIND.value,
          MountType.TMPFS.value,
          MountType.PROC.value,
      ):
        raise ValueError(
            f"Invalid mount type '{m_type}'. Valid types are 'bind', 'tmpfs',"
            " 'proc'."
        )
    else:
      raise TypeError(
          f"Mount type must be a MountType enum or str, got {type(m_type)}"
      )

    if type_str == MountType.BIND.value:
      if not m_source or not isinstance(m_source, str) or not m_source.strip():
        raise ValueError(f"Bind mount source cannot be empty: {m_source!r}")
      clean_source = os.path.abspath(m_source)
      normalized.append(
          Mount(
              destination=clean_dest,
              source=clean_source,
              type=MountType.BIND,
              readonly=bool(m_readonly),
          )
      )
    elif type_str == MountType.TMPFS.value:
      normalized.append(
          Mount(
              destination=clean_dest,
              source="tmpfs",
              type=MountType.TMPFS,
              readonly=False,
          )
      )
    elif type_str == MountType.PROC.value:
      normalized.append(
          Mount(
              destination=clean_dest,
              source="proc",
              type=MountType.PROC,
              readonly=False,
          )
      )

  return normalized


class Sandbox:
  """Represents a running gVisor sandbox."""

  def __init__(
      self,
      runtime_dir: Optional[str] = None,
      sandbox_id: Optional[str] = None,
      network: Union[NetworkMode, str] = NetworkMode.NONE,
      env: Optional[Union[List[str], Dict[str, str]]] = None,
      mounts: Optional[Sequence[Union[Mount, Dict[str, Any]]]] = None,
      working_dir: str = "/",
  ):
    """Initializes and starts a new sandbox.

    Args:
      runtime_dir: Custom runtime directory where bundle and state files are
        written. If not set, a temporary directory is created.
      sandbox_id: Specific sandbox ID. If not set, a unique ID is generated
        automatically.
      network: The networking mode for runsc ('none', 'sandbox', 'host', or
        NetworkMode enum). Defaults to NetworkMode.NONE ('none').
      env: Optional environment variables for the sandbox container.
      mounts: Optional sequence of Mount objects or dicts defining mounts.
      working_dir: The initial working directory inside the sandbox. Relative
        paths are normalized relative to container root ('/'). Defaults to "/".

    Raises:
      Error: If sandbox creation fails.
      ValueError: If an invalid network mode, working_dir, mount, or environment
        variable format is provided.
      TypeError: If env, mounts, or network has an invalid type.
    """
    if isinstance(network, NetworkMode):
      self._network = network.value
    elif isinstance(network, str):
      mode_lower = network.lower()
      if mode_lower not in (
          NetworkMode.NONE.value,
          NetworkMode.HOST.value,
          NetworkMode.SANDBOX.value,
      ):
        raise ValueError(
            f"Invalid network mode '{network}'. Valid options are 'none',"
            " 'host', 'sandbox'."
        )
      self._network = mode_lower
    else:
      raise TypeError(
          f"network must be a NetworkMode or str, got {type(network)}"
      )

    self._env = env
    self._working_dir = _normalize_working_dir(working_dir)
    self._mounts = _normalize_mounts(mounts)
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
        raise Error(f"failed to create runtime directory: {e}") from e
      self._owns_runtime_dir = True
    else:
      self._runtime_dir = runtime_dir
      self._owns_runtime_dir = False

    self._id = sandbox_id or self._generate_id()

    try:
      if os.geteuid() != 0 and self._network == NetworkMode.SANDBOX.value:
        raise Error("sandbox networking requires running as root")

      self._state_dir = os.path.join(self._runtime_dir, "state")
      try:
        os.makedirs(self._state_dir, mode=0o700, exist_ok=True)
      except OSError as e:
        raise Error(f"failed to create sandbox state directory: {e}") from e

      # Verify permissions (mode might be different if directory already
      # existed).
      try:
        stat_info = os.stat(self._state_dir)
        if (stat_info.st_mode & 0o777) != 0o700:
          os.chmod(self._state_dir, 0o700)
      except OSError as e:
        raise Error(
            "sandbox state directory has incorrect permissions and failed to"
            f" chmod: {e}"
        ) from e

      self._bundle_dir = self._create_bundle()

      # Launch the sandbox in detached mode.
      args = ["--root", self._state_dir]
      if os.geteuid() != 0:
        args.append("--ignore-cgroups")

      args.append(f"--network={self._network}")

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
        raise Error("sandbox creation timed out (runsc run hung)") from e
      except subprocess.CalledProcessError as e:
        stderr_content = ""
        if os.path.exists(stderr_path):
          try:
            with open(stderr_path, "r", errors="replace") as f:
              stderr_content = f.read()
          except OSError:
            pass
        raise Error(
            "failed to create sandbox via subprocess: exit code"
            f" {e.returncode}, stderr: {stderr_content}"
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
    raise Error("runsc binary is not found")

  def _create_bundle(self) -> str:
    """Creates the OCI bundle directory and config.json.

    Returns:
      The path to the created bundle directory.

    Raises:
      Error: If bundle creation fails.
    """
    bundle_dir = os.path.join(self._runtime_dir, self._id)
    rootfs_dir = os.path.join(bundle_dir, "rootfs")
    try:
      os.makedirs(rootfs_dir, mode=0o755, exist_ok=True)
    except OSError as e:
      raise Error(f"failed to create bundle directories: {e}") from e

    namespaces = [
        {"type": "pid"},
        {"type": "mount"},
        {"type": "uts"},
        {"type": "ipc"},
    ]
    if os.geteuid() != 0:
      namespaces.append({"type": "user"})
    if self._network == NetworkMode.SANDBOX.value:
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

    for m in self._mounts:
      if m.type == MountType.BIND:
        opts = ["rbind", "ro" if m.readonly else "rw"]
        mounts.append({
            "destination": m.destination,
            "type": "bind",
            "source": m.source,
            "options": opts,
        })
      elif m.type == MountType.TMPFS:
        mounts.append({
            "destination": m.destination,
            "type": "tmpfs",
            "source": "tmpfs",
        })
      elif m.type == MountType.PROC:
        mounts.append({
            "destination": m.destination,
            "type": "proc",
            "source": "proc",
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

    base_env = {"PATH": "/bin:/usr/bin:/usr/local/bin"}
    process_env = _normalize_env(self._env, base_env=base_env)

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
            "cwd": self._working_dir,
            "env": process_env,
        },
        "mounts": mounts,
        "linux": linux,
    }

    config_path = os.path.join(bundle_dir, "config.json")
    try:
      with open(config_path, "w") as f:
        json.dump(spec, f, indent=2)
    except OSError as e:
      raise Error(f"failed to create config.json: {e}") from e

    return bundle_dir

  def exec(
      self,
      cmd: str,
      *args: str,
      env: Optional[Union[List[str], Dict[str, str]]] = None,
      cwd: Optional[str] = None,
      timeout: Optional[float] = None,
  ) -> Tuple[str, str]:
    """Runs the given command inside the running sandbox.

    Args:
      cmd: The command to run.
      *args: Arguments to the command.
      env: Optional environment variables for this command execution.
      cwd: Optional working directory for this command execution. Relative paths
        are normalized relative to container root ('/').
      timeout: Timeout in seconds.

    Returns:
      A tuple of (stdout, stderr) strings.

    Raises:
      Error: If the command execution fails or times out.
      ValueError: If environment variable formatting or cwd is invalid.
      TypeError: If env or cwd has an invalid type.
    """
    runsc_args = ["--root", self._state_dir, "exec"]
    if cwd is not None:
      clean_cwd = _normalize_working_dir(cwd, param_name="cwd")
      runsc_args.extend(["--cwd", clean_cwd])
    if env:
      for env_str in _normalize_env(env):
        runsc_args.extend(["--env", env_str])
    runsc_args.extend([self._id, cmd] + list(args))
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
      raise Error(f"exec timed out after {timeout} seconds") from e
    except subprocess.CalledProcessError as e:
      raise Error(f"exec failed: {e.stderr}") from e

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
