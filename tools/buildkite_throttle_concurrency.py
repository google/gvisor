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
"""Dynamically calculates Buildkite pipeline concurrency limit based on pool load."""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request


# pylint: disable=g-doc-args,g-doc-return-or-yield
def get_concurrency_limit(
    max_vm_pool_size: int,
    default_concurrency: int,
    min_concurrency: int,
    max_concurrency: int,
) -> int:
  """Calculates the target concurrency limit based on env and Buildkite state."""
  # 1. Check explicit environment override.
  explicit_limit = os.environ.get("BUILDKITE_CONCURRENCY_LIMIT")
  if explicit_limit and explicit_limit.isdigit():
    return int(explicit_limit)

  # 2. For master branch continuous builds, allow up to max_concurrency.
  if os.environ.get("BUILDKITE_BRANCH") == "master":
    return max_concurrency

  # 3. Query Buildkite API for currently running builds.
  token = os.environ.get("BUILDKITE_API_TOKEN")
  if token:
    org = os.environ.get("BUILDKITE_ORGANIZATION_SLUG", "gvisor")
    pip = os.environ.get("BUILDKITE_PIPELINE_SLUG", "gvisor")
    # Validate slugs to prevent URL tampering/injection
    if re.match(r"^[a-zA-Z0-9_-]+$", org) and re.match(
        r"^[a-zA-Z0-9_-]+$", pip
    ):
      url = f"https://api.buildkite.com/v2/organizations/{org}/pipelines/{pip}/builds?state=running"
      req = urllib.request.Request(
          url, headers={"Authorization": f"Bearer {token}"}
      )
      try:
        with urllib.request.urlopen(req, timeout=5) as response:
          builds = json.loads(response.read().decode("utf-8"))
          active_builds = max(len(builds), 1)
          calc = max_vm_pool_size // active_builds
          return max(min_concurrency, min(calc, max_concurrency))
      except (
          urllib.error.URLError,
          ValueError,
          KeyError,
          json.JSONDecodeError,
          OSError,
      ):
        print(
            "Warning: Failed to query Buildkite API, using default"
            " concurrency.",
            file=sys.stderr,
        )

  # 4. Fallback to default fair-share concurrency.
  return default_concurrency


def main():
  parser = argparse.ArgumentParser(
      description="Calculate Buildkite concurrency."
  )
  parser.add_argument("--max-vm-pool-size", type=int, default=300)
  parser.add_argument("--default-concurrency", type=int, default=75)
  parser.add_argument("--min-concurrency", type=int, default=25)
  parser.add_argument("--max-concurrency", type=int, default=150)
  args = parser.parse_args()

  limit = get_concurrency_limit(
      args.max_vm_pool_size,
      args.default_concurrency,
      args.min_concurrency,
      args.max_concurrency,
  )
  print(limit)


if __name__ == "__main__":
  main()
