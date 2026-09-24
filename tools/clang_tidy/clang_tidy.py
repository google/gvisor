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

"""Runs clang-tidy over the C++ sources in compile_commands.json."""

import argparse
import concurrent.futures
import json
import os
import pathlib
import re
import subprocess
import sys

_FINDING = re.compile(r"^(?P<file>.+?):\d+:\d+: warning: .*\[[\w.-]+\]\s*$")
_ERROR = re.compile(r"^(?P<file>.+?):\d+:\d+: error: ")


def _sources(database, workspace):
  """Returns the workspace-relative sources named in the database."""

  with open(database) as f:
    entries = json.load(f)

  out = []
  seen = set()
  for entry in entries:
    path = pathlib.Path(os.path.realpath(entry["file"]))
    try:
      relative = path.relative_to(workspace)
    except ValueError:
      continue
    if relative in seen:
      continue
    seen.add(relative)
    out.append(relative)
  return sorted(out)


def _analyze(clang_tidy, database_dir, config_file, workspace, source):
  """Runs clang-tidy on one source, returning its findings and errors."""

  proc = subprocess.run(
      [
          clang_tidy,
          "-p",
          str(database_dir),
          f"--config-file={config_file}",
          "--quiet",
          str(workspace / source),
      ],
      capture_output=True,
      text=True,
      check=False,
  )

  findings = []
  errors = []
  for line in proc.stdout.splitlines():
    if _ERROR.match(line):
      errors.append(line)
    elif _FINDING.match(line):
      findings.append(line)
  return source, findings, errors


def main():
  parser = argparse.ArgumentParser(
      description=(
          "Runs clang-tidy over the C++ sources in compile_commands.json."
      )
  )
  parser.add_argument("--clang-tidy", default="clang-tidy")
  parser.add_argument("--config-file", required=True)
  parser.add_argument("--database", required=True)
  parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
  args = parser.parse_args()

  workspace = pathlib.Path(os.path.realpath(pathlib.Path(args.database).parent))
  sources = _sources(args.database, workspace)
  if not sources:
    print(f"clang-tidy: no sources in {args.database}", file=sys.stderr)
    return 1

  findings = {}
  errors = {}
  with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
    futures = [
        pool.submit(
            _analyze,
            args.clang_tidy,
            workspace,
            args.config_file,
            workspace,
            source,
        )
        for source in sources
    ]
    for future in concurrent.futures.as_completed(futures):
      source, found, failed = future.result()
      if found:
        findings[source] = found
      if failed:
        errors[source] = failed

  if errors:
    print(
        f"clang-tidy: {len(errors)} file(s) failed to compile; the "
        "compilation database may be stale",
        file=sys.stderr,
    )
    for source in sorted(errors):
      for line in errors[source][:5]:
        print(f"  {line}", file=sys.stderr)
    return 1

  for source in sorted(findings):
    for line in findings[source]:
      print(line)

  if findings:
    print(file=sys.stderr)
    print(
        f"clang-tidy: {len(findings)} file(s) have findings.",
        file=sys.stderr,
    )
    return 1

  print(f"clang-tidy: {len(sources)} sources analyzed.")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
