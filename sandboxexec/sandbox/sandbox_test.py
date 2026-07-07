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
import tempfile
import unittest

from sandboxexec.sandbox import sandbox


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
    enable_networking = os.geteuid() == 0
    # Create the background sandbox
    with sandbox.Sandbox(enable_networking=enable_networking) as sb:
      # Execute dmesg in the gVisor sandbox.
      stdout, _ = sb.exec("dmesg")
      self.assertIn("Starting gVisor", stdout)

  def test_exec_timeout(self):
    enable_networking = os.geteuid() == 0
    with sandbox.Sandbox(enable_networking=enable_networking) as sb:
      with self.assertRaises(sandbox.SandboxError) as ctx:
        sb.exec("sleep", "10", timeout=1)
      self.assertIn("exec timed out", str(ctx.exception))

  def test_exec_with_args(self):
    enable_networking = os.geteuid() == 0
    with sandbox.Sandbox(enable_networking=enable_networking) as sb:
      stdout, _ = sb.exec("echo", "hello", "sandbox")
      self.assertEqual(stdout.strip(), "hello sandbox")

  def test_exec_invalid_command_or_args(self):
    enable_networking = os.geteuid() == 0
    with sandbox.Sandbox(enable_networking=enable_networking) as sb:
      with self.assertRaises(sandbox.SandboxError) as ctx:
        sb.exec("nonexistent_command_xyz123")
      self.assertIn("exec failed", str(ctx.exception))

      with self.assertRaises(sandbox.SandboxError) as ctx:
        sb.exec("ls", "--invalid-flag-xyz123")
      self.assertIn("exec failed", str(ctx.exception))


  def test_sandbox_options(self):
    enable_networking = os.geteuid() == 0
    with tempfile.TemporaryDirectory() as runtime_dir:
      sandbox_id = "iwillbeasandbox"
      with sandbox.Sandbox(
          runtime_dir=runtime_dir,
          sandbox_id=sandbox_id,
          enable_networking=enable_networking,
      ) as sb:
        self.assertTrue(sb.bundle_dir.startswith(runtime_dir))
        self.assertEqual(sb.id, sandbox_id)

  def test_non_root_networking_error(self):
    if os.geteuid() == 0:
      self.skipTest("this test must be run as non-root")

    before_tmp = set(os.listdir(tempfile.gettempdir()))
    with self.assertRaises(sandbox.SandboxError) as ctx:
      sandbox.Sandbox(enable_networking=True)
    after_tmp = set(os.listdir(tempfile.gettempdir()))

    self.assertIn(
        "enabling networking requires running as root", str(ctx.exception)
    )
    leaked = [f for f in after_tmp - before_tmp if f.startswith("gvisor-sandbox-")]
    self.assertEqual(leaked, [])


  def test_create_bundle(self):
    # Test the internal _create_bundle method to verify config.json
    for enable_networking in [False, True]:
      with self.subTest(enable_networking=enable_networking):
        sandbox_id = "test-sandbox"

        if enable_networking and os.geteuid() != 0:
          continue

        with tempfile.TemporaryDirectory() as temp_dir:
          try:
            sb = sandbox.Sandbox(
                runtime_dir=temp_dir,
                sandbox_id=sandbox_id,
                enable_networking=enable_networking,
            )
          except sandbox.SandboxError as e:
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
            if enable_networking:
              expected_types.add("network")

            self.assertEqual(namespace_types, expected_types)
          finally:
            sb.close()

          self.assertFalse(os.path.exists(bundle_dir))

  def test_runtime_dir_ownership_and_cleanup(self):
    enable_networking = os.geteuid() == 0

    # Auto-created runtime directory should be deleted on close.
    sb = sandbox.Sandbox(enable_networking=enable_networking)
    auto_runtime_dir = sb._runtime_dir
    self.assertTrue(os.path.exists(auto_runtime_dir))
    sb.close()
    self.assertFalse(os.path.exists(auto_runtime_dir))

    # Custom runtime directory should not be deleted on close.
    with tempfile.TemporaryDirectory() as custom_dir:
      sb = sandbox.Sandbox(
          runtime_dir=custom_dir, enable_networking=enable_networking
      )
      sb.close()
      self.assertTrue(os.path.exists(custom_dir))

  def test_close_idempotent(self):
    enable_networking = os.geteuid() == 0
    sb = sandbox.Sandbox(enable_networking=enable_networking)
    sb.close()
    # Repeating close() should be a safe no-op.
    sb.close()


if __name__ == "__main__":
  unittest.main()
