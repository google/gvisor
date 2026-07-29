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

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def _bazel(*args):
  """Runs bazel, returning its stdout."""

  return subprocess.run(
      ("bazel",) + args, check=True, text=True, stdout=subprocess.PIPE
  ).stdout


def _compile_actions(targets):
  """Yields the C++ compile actions for the targets' dependencies."""

  query = 'mnemonic("CppCompile", deps({}))'.format(" union ".join(targets))
  return json.loads(
      _bazel("aquery", "--output=jsonproto", "--noshow_progress", query)
  )["actions"]


def main():
  parser = argparse.ArgumentParser(
      description="Generates compile_commands.json for gVisor's C++ code."
  )
  parser.add_argument(
      "targets",
      nargs="*",
      default=["//test/..."],
      help="Bazel targets to index (default: %(default)s).",
  )
  args = parser.parse_args()
  targets = args.targets

  workspace = Path(__file__).parent.parent.resolve()
  os.chdir(workspace)

  _bazel(
      "build",
      "--aspects=//tools:cc_compile_inputs.bzl%cc_compile_inputs",
      "--output_groups=cc_compile_inputs",
      *targets,
  )
  execroot = Path(_bazel("info", "execution_root").strip())

  database = []
  seen = set()
  for action in _compile_actions(targets):
    arguments = action["arguments"]
    if "-c" not in arguments:
      continue
    source = Path(arguments[arguments.index("-c") + 1])

    # Skip third-party code.
    if "external" in source.parts:
      continue

    # A source can be compiled by several actions.
    # Skip all but the first.
    if source in seen:
      continue
    seen.add(source)

    # Add the compile command to the database.
    database.append({
        # Special-case for generated files in bazel-out/. When LSP jump is used,
        # it will navigate to the execroot path, so match that in the database.
        "file": str(
            (execroot if source.parts[0] == "bazel-out" else workspace) / source
        ),
        "directory": str(execroot),
        "arguments": arguments,
    })

  path = os.path.join(workspace, "compile_commands.json")
  with open(path, "w") as out:
    json.dump(database, out, indent=4)
  print(f"generated {path}: {len(database)} entries")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
