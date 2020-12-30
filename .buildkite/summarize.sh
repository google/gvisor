#!/bin/bash

# Copyright 2020 The gVisor Authors.
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

set -xeou pipefail

# This script collects metadata fragments produced by individual test shards in
# .buildkite/hooks/postcommand, and aggregates these into a single annotation
# that is posted to the build. In the future, this will include coverage.

# Start the summary.
declare summary
declare status
summary=$(mktemp --tmpdir summary.XXXXXX)
status="info"

# Download all outputs.
declare outputs
outputs=$(mktemp -d --tmpdir outputs.XXXXXX)
if buildkite-agent artifact download '**/*.output' "${outputs}"; then
  status="error"
  echo "## Failures" >> "${summary}"
  find "${outputs}" -type f -print | xargs -r -n 1 cat | sort >> "${summary}"
fi
rm -rf "${outputs}"

# Attempt to find profiles, if there are any.
declare profiles
profiles=$(mktemp -d --tmpdir profiles.XXXXXX)
if buildkite-agent artifact download '**/*.profile_output' "${profiles}"; then
  echo "## Profiles" >> "${summary}"
  find "${profiles}" -type f -print | xargs -r -n 1 cat | sort >> "${summary}"
fi
rm -rf "${profiles}"

# Upload the final annotation.
if [[ -s "${summary}" ]]; then
  cat "${summary}" | buildkite-agent annotate --style "${status}"
fi
rm -rf "${summary}"
