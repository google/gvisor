#!/usr/bin/env python3

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Checks failure propagation through the public lint entrypoint."""

import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


LINT = pathlib.Path(sys.argv.pop(1)).absolute()


class LintTest(unittest.TestCase):

  def setUp(self) -> None:
    self.temp = tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"])
    self.addCleanup(self.temp.cleanup)
    self.root = pathlib.Path(self.temp.name)
    self.cache = self.root / "cache"
    self.bin = self.root / "bin"
    self.goroot = self.root / "go"
    self.env = dict(os.environ, LINT_CACHE_DIR=str(self.cache))
    self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
    self.cache.mkdir()
    self.bin.mkdir()
    (self.goroot / "bin").mkdir(parents=True)
    self.versions = dict(
        re.findall(
            r'^declare -r ([A-Z_]+)_VERSION="([^"]+)"$',
            LINT.read_text(),
            re.MULTILINE,
        )
    )
    self.tool(
        self.bin / "go", "printf '%s\\n' " + shlex.quote(str(self.goroot))
    )
    self.tool(self.bin / "git", "printf 'tracked source\\0'")
    self.tool(self.bin / "curl", "echo unexpected-download >&2; exit 42")
    for name in ("gofmt", "clang-format", "buildifier"):
      self.tool(self.formatter(name), "exit 0")

  def tool(self, path: pathlib.Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)

  def formatter(self, name: str) -> pathlib.Path:
    if name == "gofmt":
      return self.goroot / "bin" / "gofmt"
    version = self.versions[name.upper().replace("-", "_")]
    return self.cache / f"{name}-{version}"

  def lint(self, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(LINT), *args],
        env=self.env,
        capture_output=True,
        text=True,
        check=False,
    )

  def assert_failed(
      self, result: subprocess.CompletedProcess[str], name: str
  ) -> None:
    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
    self.assertIn(f"FAIL  {name}", result.stderr)
    self.assertNotIn("lint: all checks passed.", result.stderr)

  def test_formatter_status(self) -> None:
    names = ("gofmt", "clang-format", "buildifier")
    success = self.lint(*names)
    self.assertEqual(success.returncode, 0, success.stderr)
    for name in names:
      self.assertIn(f"PASS  {name}", success.stderr)
    # Exercise plain pipeline, captured output and --fix status handling.
    for args in (
        ("gofmt",),
        ("clang-format",),
        ("buildifier",),
        ("--fix", "gofmt"),
    ):
      name = args[-1]
      with self.subTest(args=args):
        self.tool(self.formatter(name), "exit 7")
        self.assert_failed(self.lint(*args), name)
        self.tool(self.formatter(name), "exit 0")

  def test_diagnostics_and_continuation(self) -> None:
    self.tool(
        self.formatter("clang-format"), "echo formatter-crashed >&2; exit 7"
    )
    result = self.lint("clang-format", "buildifier")
    self.assert_failed(result, "clang-format")
    self.assertIn("formatter-crashed", result.stderr)
    self.assertIn("PASS  buildifier", result.stderr)

  def test_installer_failure(self) -> None:
    # Both failures occur in an installer command substitution. A stale cache
    # entry must not be made executable by commands following the failure.
    self.formatter("buildifier").chmod(0o644)
    result = self.lint("buildifier")
    self.assert_failed(result, "buildifier")
    self.assertIn("unexpected-download", result.stderr)
    self.assertEqual(self.formatter("buildifier").stat().st_mode & 0o111, 0)
    # mktemp adds another substitution, whose status local must not mask.
    self.tool(self.bin / "mktemp", "echo temporary-file-failed >&2; exit 7")
    result = self.lint("buildifier", "gofmt")
    self.assert_failed(result, "buildifier")
    self.assertIn("temporary-file-failed", result.stderr)
    self.assertNotIn("unexpected-download", result.stderr)
    self.assertIn("PASS  gofmt", result.stderr)

  def test_failed_file_selection(self) -> None:
    # The last spelling selection succeeds; it must not hide an earlier
    # failed list operation in the same pipeline.
    self.tool(self.bin / "git", 'case "$4" in "*.md") exit 7;; esac; exit 0')
    (self.cache / f"codespell-{self.versions['CODESPELL']}").mkdir()
    self.tool(self.bin / "python3", "exit 0")
    self.assert_failed(self.lint("spelling"), "spelling")


if __name__ == "__main__":
  unittest.main()
