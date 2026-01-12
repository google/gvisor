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

"""Portable realpath with -m-like semantics."""

import os
import sys


def _realpath(path: str) -> str:
  # realpath -m resolves symlinks and normalizes even if path doesn't exist.
  return os.path.realpath(path)


def main() -> int:
  args = sys.argv[1:]
  if not args:
    return 1
  for path in args:
    sys.stdout.write(_realpath(path))
    sys.stdout.write("\n")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
