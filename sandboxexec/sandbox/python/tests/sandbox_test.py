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

"""Tests for the gVisor sandbox Python binding."""

import glob
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from gvisor import sandbox


def find_runsc() -> str:
  """Finds the runsc binary in the test environment."""
  if "RUNSC_PATH" in os.environ:
    return os.environ["RUNSC_PATH"]

  # Try to find via runfiles directory recursively.
  for env_var in ["RUNFILES_DIR", "PYTHON_RUNFILES"]:
    runfiles_dir = os.environ.get(env_var)
    if runfiles_dir:
      pattern = os.path.join(runfiles_dir, "**", "runsc/runsc")
      matches = glob.glob(pattern, recursive=True)
      matches = [m for m in matches if os.path.isfile(m)]
      if matches:
        return matches[0]

  # Fallback to PATH.
  path = shutil.which("runsc")
  if path:
    return path

  raise RuntimeError("runsc binary not found")


def setUpModule():
  try:
    os.environ["RUNSC_PATH"] = find_runsc()
  except RuntimeError as e:
    raise unittest.SkipTest(str(e))


class SandboxTest(unittest.TestCase):

  def test_exec_dmesg(self):
    # Create the background sandbox (default network="none" works for
    # non-root and root).
    with sandbox.Sandbox() as sb:
      # Execute dmesg in the gVisor sandbox.
      stdout, _ = sb.exec("dmesg")
      self.assertIn("Starting gVisor", stdout)

  def test_exec_timeout(self):
    with sandbox.Sandbox() as sb:
      with self.assertRaises(sandbox.Error) as ctx:
        sb.exec("sleep", "10", timeout=1)
      self.assertIn("exec timed out", str(ctx.exception))

  def test_exec_with_args(self):
    with sandbox.Sandbox() as sb:
      stdout, _ = sb.exec("echo", "hello", "sandbox")
      self.assertEqual(stdout.strip(), "hello sandbox")

  def test_exec_invalid_command_or_args(self):
    with sandbox.Sandbox() as sb:
      with self.assertRaises(sandbox.Error) as ctx:
        sb.exec("nonexistent_command_xyz123")
      self.assertIn("exec failed", str(ctx.exception))

      with self.assertRaises(sandbox.Error) as ctx:
        sb.exec("ls", "--invalid-flag-xyz123")
      self.assertIn("exec failed", str(ctx.exception))

  def test_sandbox_options(self):
    with tempfile.TemporaryDirectory() as runtime_dir:
      sandbox_id = "iwillbeasandbox"
      with sandbox.Sandbox(
          runtime_dir=runtime_dir,
          sandbox_id=sandbox_id,
          network=sandbox.NetworkMode.HOST,
      ) as sb:
        self.assertTrue(sb.bundle_dir.startswith(runtime_dir))
        self.assertEqual(sb.id, sandbox_id)

  def test_non_root_networking_error(self):
    if os.geteuid() == 0:
      self.skipTest("this test must be run as non-root")

    before_tmp = set(os.listdir(tempfile.gettempdir()))
    with self.assertRaises(sandbox.Error) as ctx:
      sandbox.Sandbox(network=sandbox.NetworkMode.SANDBOX)
    after_tmp = set(os.listdir(tempfile.gettempdir()))

    self.assertIn(
        "sandbox networking requires running as root", str(ctx.exception)
    )
    leaked = [
        f for f in after_tmp - before_tmp if f.startswith("gvisor-sandbox-")
    ]
    self.assertEqual(leaked, [])

  def test_create_bundle(self):
    # Test the internal _create_bundle method to verify config.json
    for net_mode in [
        sandbox.NetworkMode.NONE,
        sandbox.NetworkMode.HOST,
        sandbox.NetworkMode.SANDBOX,
    ]:
      with self.subTest(network=net_mode):
        sandbox_id = "test-sandbox"

        if net_mode == sandbox.NetworkMode.SANDBOX and os.geteuid() != 0:
          continue

        with tempfile.TemporaryDirectory() as temp_dir:
          try:
            sb = sandbox.Sandbox(
                runtime_dir=temp_dir,
                sandbox_id=sandbox_id,
                network=net_mode,
            )
          except sandbox.Error as e:
            self.fail(f"Failed to create sandbox: {e}")

          try:
            bundle_dir = sb.bundle_dir
            expected_bundle_dir = os.path.join(temp_dir, sandbox_id)
            self.assertEqual(bundle_dir, expected_bundle_dir)

            config_path = os.path.join(bundle_dir, "config.json")
            self.assertTrue(os.path.exists(config_path))

            with open(config_path, "r") as f:
              spec = json.load(f)

            self.assertEqual(spec.get("ociVersion"), "1.0.0")
            self.assertEqual(spec.get("root", {}).get("path"), "rootfs")
            self.assertTrue(spec.get("root", {}).get("readonly"))

            namespaces = spec.get("linux", {}).get("namespaces", [])
            namespace_types = {ns.get("type") for ns in namespaces}

            expected_types = {"pid", "mount", "uts", "ipc"}
            if os.geteuid() != 0:
              expected_types.add("user")
            if net_mode == sandbox.NetworkMode.SANDBOX:
              expected_types.add("network")

            self.assertEqual(namespace_types, expected_types)
          finally:
            sb.close()

          self.assertFalse(os.path.exists(bundle_dir))

  def test_init_env_list_and_dict(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      sb = sandbox.Sandbox(
          runtime_dir=temp_dir,
          env=["FOO=bar", "BAZ=123"],
      )
      config_path = os.path.join(sb.bundle_dir, "config.json")
      with open(config_path, "r") as f:
        spec = json.load(f)
      self.assertEqual(
          spec["process"]["env"],
          ["PATH=/bin:/usr/bin:/usr/local/bin", "FOO=bar", "BAZ=123"],
      )
      sb.close()

      sb_dict = sandbox.Sandbox(
          runtime_dir=temp_dir,
          env={"FOO": "bar", "BAZ": "123"},
      )
      config_path = os.path.join(sb_dict.bundle_dir, "config.json")
      with open(config_path, "r") as f:
        spec = json.load(f)
      self.assertEqual(
          spec["process"]["env"],
          ["PATH=/bin:/usr/bin:/usr/local/bin", "FOO=bar", "BAZ=123"],
      )
      sb_dict.close()

  def test_init_env_overrides_path(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      sb = sandbox.Sandbox(
          runtime_dir=temp_dir,
          env={"PATH": "/bin:/usr/bin:/custom/path"},
      )
      config_path = os.path.join(sb.bundle_dir, "config.json")
      with open(config_path, "r") as f:
        spec = json.load(f)
      self.assertEqual(
          spec["process"]["env"], ["PATH=/bin:/usr/bin:/custom/path"]
      )
      sb.close()

  def test_init_env_malformed_raises_error(self):
    with self.assertRaises(ValueError) as ctx:
      sandbox.Sandbox(env=["NO_EQUALS"])
    self.assertIn("Invalid environment variable format", str(ctx.exception))

    with self.assertRaises(ValueError) as ctx:
      sandbox.Sandbox(env={"KEY=FOO": "val"})
    self.assertIn(
        "Environment variable key cannot contain '='", str(ctx.exception)
    )

    with self.assertRaises(TypeError) as ctx:
      sandbox.Sandbox(env=123)
    self.assertIn(
        "env must be a list of 'KEY=VALUE' strings or a dict",
        str(ctx.exception),
    )

  @mock.patch("subprocess.run")
  def test_exec_env_flags(self, mock_run):
    mock_run.return_value = mock.Mock(returncode=0)
    sb = sandbox.Sandbox()
    mock_run.reset_mock()
    sb.exec("/bin/sh", "-c", "echo hi", env={"LOCAL_VAR": "test"})
    args = mock_run.call_args_list[0][0][0]
    self.assertIn("--env", args)
    self.assertIn("LOCAL_VAR=test", args)

    mock_run.reset_mock()
    sb.exec("/bin/sh", "-c", "echo hi", env=["LOCAL_VAR=test"])
    args = mock_run.call_args_list[0][0][0]
    self.assertIn("--env", args)
    self.assertIn("LOCAL_VAR=test", args)

    with self.assertRaises(ValueError) as ctx:
      sb.exec("/bin/sh", "-c", "echo hi", env=["NO_EQUALS"])
    self.assertIn("Invalid environment variable format", str(ctx.exception))
    sb.close()

  def test_runtime_dir_ownership_and_cleanup(self):
    # Auto-created runtime directory should be deleted on close.
    sb = sandbox.Sandbox()
    auto_runtime_dir = sb._runtime_dir
    self.assertTrue(os.path.exists(auto_runtime_dir))
    sb.close()
    self.assertFalse(os.path.exists(auto_runtime_dir))

    # Custom runtime directory should not be deleted on close.
    with tempfile.TemporaryDirectory() as custom_dir:
      sb = sandbox.Sandbox(runtime_dir=custom_dir)
      sb.close()
      self.assertTrue(os.path.exists(custom_dir))

  def test_close_idempotent(self):
    sb = sandbox.Sandbox()
    sb.close()
    # Repeating close() should be a safe no-op.
    sb.close()

  @mock.patch("tempfile.mkdtemp")
  def test_runtime_dir_creation_error(self, mock_mkdtemp):
    mock_mkdtemp.side_effect = OSError("mock disk error")
    with self.assertRaises(sandbox.Error) as ctx:
      sandbox.Sandbox()
    self.assertIn("failed to create runtime directory", str(ctx.exception))

  @mock.patch("os.makedirs")
  def test_state_dir_creation_error(self, mock_makedirs):
    def side_effect(path, **_kwargs):
      if path.endswith("state"):
        raise OSError("mock permission denied")

    mock_makedirs.side_effect = side_effect
    with tempfile.TemporaryDirectory() as runtime_dir:
      with self.assertRaises(sandbox.Error) as ctx:
        sandbox.Sandbox(runtime_dir=runtime_dir)
      self.assertIn(
          "failed to create sandbox state directory", str(ctx.exception)
      )

  def test_create_bundle_makedirs_error(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      # Bypass __init__ to test _create_bundle logic
      sb = sandbox.Sandbox.__new__(sandbox.Sandbox)
      sb._id = "test-bundle"
      sb._runtime_dir = temp_dir
      sb._network = "none"
      with mock.patch("os.makedirs") as mock_makedirs:
        mock_makedirs.side_effect = OSError("mock disk error")
        with self.assertRaises(sandbox.Error) as ctx:
          sb._create_bundle()
        self.assertIn("failed to create bundle directories", str(ctx.exception))

  @mock.patch("subprocess.run")
  def test_sandbox_subprocess_timeout(self, mock_run):
    def side_effect(*args, **_kwargs):
      if "run" in args[0]:
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=30)
      return mock.Mock(returncode=0)

    mock_run.side_effect = side_effect
    with self.assertRaises(sandbox.Error) as ctx:
      sandbox.Sandbox()
    self.assertIn("sandbox creation timed out", str(ctx.exception))

  @mock.patch("subprocess.run")
  def test_sandbox_subprocess_error(self, mock_run):
    def side_effect(*args, **_kwargs):
      if "run" in args[0]:
        raise subprocess.CalledProcessError(returncode=1, cmd=args[0])
      return mock.Mock(returncode=0)

    mock_run.side_effect = side_effect
    with self.assertRaises(sandbox.Error) as ctx:
      sandbox.Sandbox()
    self.assertIn("failed to create sandbox via subprocess", str(ctx.exception))

  def test_invalid_networking_mode(self):  # pylint: disable=unused-argument
    with self.assertRaises(ValueError) as ctx:
      sandbox.Sandbox(network="invalid-net")
    self.assertIn(
        "Invalid network mode 'invalid-net'. Valid options are 'none', 'host',"
        " 'sandbox'.",
        str(ctx.exception),
    )

  def test_invalid_networking_type(self):
    with self.assertRaises(TypeError) as ctx:
      sandbox.Sandbox(network=123)
    self.assertIn("network must be a NetworkMode or str", str(ctx.exception))

  @mock.patch("os.geteuid", return_value=0)
  @mock.patch("subprocess.run")
  def test_network_modes(self, mock_run, mock_geteuid):  # pylint: disable=unused-argument
    mock_run.return_value = mock.Mock(returncode=0)
    for net in ["none", "sandbox", "host", sandbox.NetworkMode.HOST]:
      mock_run.reset_mock()
      sb = sandbox.Sandbox(network=net)
      args = mock_run.call_args_list[0][0][0]
      net_val = net.value if isinstance(net, sandbox.NetworkMode) else net
      self.assertIn(f"--network={net_val}", args)
      sb.close()

  @mock.patch("os.geteuid", return_value=0)
  @mock.patch("subprocess.run")
  def test_network_mode_enum_bundle(
      self, mock_run, mock_geteuid
  ):  # pylint: disable=unused-argument
    mock_run.return_value = mock.Mock(returncode=0)
    sb = sandbox.Sandbox(network=sandbox.NetworkMode.NONE)
    args = mock_run.call_args_list[0][0][0]
    self.assertIn("--network=none", args)
    config_path = os.path.join(sb.bundle_dir, "config.json")
    with open(config_path, "r") as f:
      spec = json.load(f)
    namespaces = spec.get("linux", {}).get("namespaces", [])
    namespace_types = {ns.get("type") for ns in namespaces}
    self.assertNotIn("network", namespace_types)
    sb.close()

  @mock.patch("os.geteuid", return_value=1000)
  def test_network_sandbox_nonroot_raises_error(
      self, mock_geteuid
  ):  # pylint: disable=unused-argument
    with self.assertRaises(sandbox.Error) as ctx:
      sandbox.Sandbox(network="sandbox")
    self.assertIn(
        "sandbox networking requires running as root", str(ctx.exception)
    )

  def test_network_mode_none_real_sandbox(self):
    """Verifies starting a real sandbox with network='none' without mocks."""
    with sandbox.Sandbox(network="none") as sb:
      stdout, _ = sb.exec("echo", "hello network none")
      self.assertEqual(stdout.strip(), "hello network none")
      config_path = os.path.join(sb.bundle_dir, "config.json")
      with open(config_path, "r") as f:
        spec = json.load(f)
      namespaces = spec.get("linux", {}).get("namespaces", [])
      namespace_types = {ns.get("type") for ns in namespaces}
      self.assertNotIn("network", namespace_types)

  def test_network_mode_host_real_sandbox(self):
    """Verifies starting a real sandbox with network='host' without mocks."""
    with sandbox.Sandbox(network="host") as sb:
      stdout, _ = sb.exec("echo", "hello network host")
      self.assertEqual(stdout.strip(), "hello network host")
      config_path = os.path.join(sb.bundle_dir, "config.json")
      with open(config_path, "r") as f:
        spec = json.load(f)
      namespaces = spec.get("linux", {}).get("namespaces", [])
      namespace_types = {ns.get("type") for ns in namespaces}
      self.assertNotIn("network", namespace_types)

  def test_find_runsc_not_found(self):
    old_runsc_path = os.environ.get("RUNSC_PATH")
    try:
      if "RUNSC_PATH" in os.environ:
        del os.environ["RUNSC_PATH"]

      with mock.patch("shutil.which", return_value=None):
        with self.assertRaises(sandbox.Error) as ctx:
          sandbox.Sandbox()
        self.assertIn("runsc binary is not found", str(ctx.exception))
    finally:
      if old_runsc_path is not None:
        os.environ["RUNSC_PATH"] = old_runsc_path

  def test_custom_bind_mount_readonly(self):
    with tempfile.TemporaryDirectory() as temp_host_dir:
      witness_file = os.path.join(temp_host_dir, "witness.txt")
      with open(witness_file, "w") as f:
        f.write("hello-mount")

      with sandbox.Sandbox(
          mounts=[
              sandbox.Mount.bind(
                  source=temp_host_dir,
                  destination="/mnt/host_share",
                  readonly=True,
              ),
          ],
      ) as sb:
        stdout, _ = sb.exec("cat", "/mnt/host_share/witness.txt")
        self.assertEqual(stdout.strip(), "hello-mount")

        with self.assertRaises(sandbox.Error) as ctx:
          sb.exec("sh", "-c", "echo test > /mnt/host_share/test.txt")
        self.assertIn("exec failed", str(ctx.exception))

  def test_custom_bind_mount_readwrite(self):
    with tempfile.TemporaryDirectory() as temp_host_dir:
      with sandbox.Sandbox(
          mounts=[
              sandbox.Mount.bind(
                  source=temp_host_dir,
                  destination="/mnt/host_share",
                  readonly=False,
              ),
          ],
      ) as sb:
        sb.exec(
            "sh",
            "-c",
            "echo hello-write > /mnt/host_share/file.txt",
        )

      host_file = os.path.join(temp_host_dir, "file.txt")
      self.assertTrue(os.path.exists(host_file))
      with open(host_file, "r") as f:
        self.assertEqual(f.read().strip(), "hello-write")

  def test_custom_tmpfs_mount(self):
    with sandbox.Sandbox(
        mounts=[sandbox.Mount.tmpfs("/mnt/scratch")],
    ) as sb:
      sb.exec("sh", "-c", "echo hello-tmpfs > /mnt/scratch/tmp.txt")
      stdout, _ = sb.exec("cat", "/mnt/scratch/tmp.txt")
      self.assertEqual(stdout.strip(), "hello-tmpfs")

  def test_custom_proc_mount(self):
    with sandbox.Sandbox(
        mounts=[sandbox.Mount.proc("/custom_proc")],
    ) as sb:
      stdout, _ = sb.exec("cat", "/custom_proc/self/status")
      self.assertIn("Name:", stdout)

  def test_dict_mount_configuration(self):
    with tempfile.TemporaryDirectory() as temp_host_dir:
      witness_file = os.path.join(temp_host_dir, "witness.txt")
      with open(witness_file, "w") as f:
        f.write("hello-dict-mount")

      with sandbox.Sandbox(
          mounts=[
              {
                  "source": temp_host_dir,
                  "destination": "/mnt/dict_share",
                  "type": "bind",
                  "readonly": True,
              },
          ],
      ) as sb:
        stdout, _ = sb.exec("cat", "/mnt/dict_share/witness.txt")
        self.assertEqual(stdout.strip(), "hello-dict-mount")

  def test_mount_validation_errors(self):
    with self.assertRaises(ValueError) as ctx:
      sandbox.Sandbox(
          mounts=[sandbox.Mount(destination="")],
      )
    self.assertIn("Mount destination cannot be empty", str(ctx.exception))

    with self.assertRaises(ValueError) as ctx:
      sandbox.Sandbox(
          mounts=[sandbox.Mount.bind(source="", destination="/mnt")],
      )
    self.assertIn("Bind mount source cannot be empty", str(ctx.exception))

    with self.assertRaises(ValueError) as ctx:
      sandbox.Sandbox(
          mounts=[{"destination": "/mnt", "type": "invalid_type"}],
      )
    self.assertIn("Invalid mount type", str(ctx.exception))

    with self.assertRaises(ValueError) as ctx:
      sandbox.Sandbox(
          mounts=[{"destination": "/mnt", "extra_key": "val"}],
      )
    self.assertIn("Unrecognized keys in mount dict", str(ctx.exception))
    self.assertIn("extra_key", str(ctx.exception))

    with self.assertRaises(ValueError) as ctx:
      sandbox.Sandbox(
          mounts=[{"source": "/host/path"}],
      )
    self.assertIn("Mount dictionary missing 'destination'", str(ctx.exception))

    with self.assertRaises(TypeError) as ctx:
      sandbox.Sandbox(
          mounts="invalid_string_not_list",
      )
    self.assertIn("mounts must be a list or tuple", str(ctx.exception))

    with self.assertRaises(TypeError) as ctx:
      sandbox.Sandbox(
          mounts=[123],
      )
    self.assertIn(
        "Mount item must be a Mount instance or dict", str(ctx.exception)
    )

  def test_container_default_working_dir(self):
    with sandbox.Sandbox() as sb:
      stdout, _ = sb.exec("pwd")
      self.assertEqual(stdout.strip(), "/")

      config_path = os.path.join(sb.bundle_dir, "config.json")
      with open(config_path, "r") as f:
        spec = json.load(f)
      self.assertEqual(spec["process"]["cwd"], "/")

    with sandbox.Sandbox(working_dir=None) as sb:
      stdout, _ = sb.exec("pwd")
      self.assertEqual(stdout.strip(), "/")

      config_path = os.path.join(sb.bundle_dir, "config.json")
      with open(config_path, "r") as f:
        spec = json.load(f)
      self.assertEqual(spec["process"]["cwd"], "/")

  def test_container_working_dir(self):
    with sandbox.Sandbox(
        working_dir="/tmp",
    ) as sb:
      stdout, _ = sb.exec("pwd")
      self.assertEqual(stdout.strip(), "/tmp")

      config_path = os.path.join(sb.bundle_dir, "config.json")
      with open(config_path, "r") as f:
        spec = json.load(f)
      self.assertEqual(spec["process"]["cwd"], "/tmp")

  def test_container_working_dir_relative(self):
    with sandbox.Sandbox(
        working_dir="tmp/custom",
    ) as sb:
      stdout, _ = sb.exec("pwd")
      self.assertEqual(stdout.strip(), "/tmp/custom")

      config_path = os.path.join(sb.bundle_dir, "config.json")
      with open(config_path, "r") as f:
        spec = json.load(f)
      self.assertEqual(spec["process"]["cwd"], "/tmp/custom")

  def test_bad_working_dir(self):
    with self.assertRaises(ValueError) as ctx:
      sandbox.Sandbox(
          working_dir="",
      )
    self.assertIn("working directory cannot be empty", str(ctx.exception))

    with self.assertRaises(TypeError) as ctx:
      sandbox.Sandbox(
          working_dir=123,
      )
    self.assertIn("working_dir must be a str", str(ctx.exception))

  def test_exec_cwd_override(self):
    with sandbox.Sandbox(
        working_dir="/",
    ) as sb:
      stdout, _ = sb.exec("pwd")
      self.assertEqual(stdout.strip(), "/")

      stdout_custom, _ = sb.exec("pwd", cwd="/tmp")
      self.assertEqual(stdout_custom.strip(), "/tmp")

      stdout_rel, _ = sb.exec("pwd", cwd="bin")
      self.assertEqual(stdout_rel.strip(), "/bin")

  def test_exec_bad_cwd(self):
    with sandbox.Sandbox() as sb:
      with self.assertRaises(ValueError) as ctx:
        sb.exec("pwd", cwd="")
      self.assertIn("cwd cannot be empty", str(ctx.exception))

      with self.assertRaises(TypeError) as ctx:
        sb.exec("pwd", cwd=123)
      self.assertIn("cwd must be a str", str(ctx.exception))

  def test_mount_factory_methods(self):
    b = sandbox.Mount.bind("/host", "/dest", readonly=True)
    self.assertEqual(b.destination, "/dest")
    self.assertEqual(b.source, "/host")
    self.assertEqual(b.type, sandbox.MountType.BIND)
    self.assertTrue(b.readonly)

    t = sandbox.Mount.tmpfs("/tmpfs_dest")
    self.assertEqual(t.destination, "/tmpfs_dest")
    self.assertEqual(t.type, sandbox.MountType.TMPFS)

    p = sandbox.Mount.proc("/proc_dest")
    self.assertEqual(p.destination, "/proc_dest")
    self.assertEqual(p.type, sandbox.MountType.PROC)


if __name__ == "__main__":
  unittest.main()
