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

"""Checks clang-tidy process failures through the command-line entrypoint."""

import json
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest


CLANG_TIDY = pathlib.Path(sys.argv.pop(1)).absolute()


class ClangTidyTest(unittest.TestCase):

  def setUp(self) -> None:
    self.temp = tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"])
    self.addCleanup(self.temp.cleanup)
    self.root = pathlib.Path(self.temp.name)
    self.tool = self.root / "clang-tidy"
    (self.root / "source.cc").write_text("int value;\n")
    (self.root / "config.yaml").write_text("Checks: misc-include-cleaner\n")
    self.database = self.root / "compile_commands.json"
    self.database.write_text(json.dumps([{
        "file": str(self.root / "source.cc"),
        "directory": str(self.root),
        "command": "clang -c source.cc",
    }]))

  def analyze(self, body: str) -> subprocess.CompletedProcess[str]:
    self.tool.write_text("#!/bin/sh\n" + body + "\n")
    self.tool.chmod(0o755)
    return subprocess.run(
        [
            sys.executable,
            str(CLANG_TIDY),
            "--clang-tidy",
            str(self.tool),
            "--config-file",
            str(self.root / "config.yaml"),
            "--database",
            str(self.database),
            "--jobs=1",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

  def test_success(self) -> None:
    result = self.analyze("exit 0")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertIn("1 sources analyzed.", result.stdout)

  def test_exit_status_and_diagnostics(self) -> None:
    # Preserve full failure output beyond the summary's per-file error limit.
    diagnostics = "\n".join(f"diagnostic {i}" for i in range(7))
    for output in ("", diagnostics):
      with self.subTest(output=output):
        result = self.analyze(
            "printf '%s' " + shlex.quote(output) + " >&2; exit 7"
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("source.cc: clang-tidy exited with status 7", result.stderr)
        if output:
          self.assertIn(output, result.stderr)
        self.assertNotIn("sources analyzed.", result.stdout)

  def test_findings_on_both_streams(self) -> None:
    for diagnostic in (
        "source.cc:1:1: error: missing header",
        "source.cc:1:1: warning: unused include [misc-include-cleaner]",
    ):
      for stream in (1, 2):
        with self.subTest(diagnostic=diagnostic, stream=stream):
          result = self.analyze(
              "printf '%s\\n' " + shlex.quote(diagnostic) + f" >&{stream}"
          )
          self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
          self.assertIn(diagnostic, result.stdout + result.stderr)
          self.assertNotIn("sources analyzed.", result.stdout)


if __name__ == "__main__":
  unittest.main()
