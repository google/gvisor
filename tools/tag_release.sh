#!/bin/bash

# Copyright 2019 The gVisor Authors.
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

# This script will optionally map a PiperOrigin-RevId to a given commit,
# validate a provided release name, create a tag and push it. It must be
# run manually when a release is created.

set -xeuo pipefail

# Check arguments.
if [[ "$#" -ne 3 ]]; then
  echo "usage: $0 <commit|revid> <release.rc> <message-file>"
  exit 1
fi

declare -r target_commit="$1"
declare -r release="$2"
declare -r message_file="$3"

if [[ -z "${target_commit}" ]]; then
  echo "error: <commit|revid> is empty."
fi
if [[ -z "${release}" ]]; then
  echo "error: <release.rc> is empty."
fi
if ! [[ -r "${message_file}" ]]; then
  echo "error: message file '${message_file}' is not readable."
  exit 1
fi

closest_commit() {
  while read line; do
    if [[ "$line" =~ "commit " ]]; then
        current_commit="${line#commit }"
        continue
    elif [[ "$line" =~ "PiperOrigin-RevId: " ]]; then
        revid="${line#PiperOrigin-RevId: }"
        [[ "${revid}" -le "$1" ]] && break
    fi
  done
  echo "${current_commit}"
}

# Is the passed identifier a sha commit?
if ! git show "${target_commit}" &> /dev/null; then
  # Extract the commit given a piper ID.
  declare -r commit="$(git log | closest_commit "${target_commit}")"
else
  declare -r commit="${target_commit}"
fi
if ! git show "${commit}" &> /dev/null; then
  echo "unknown commit: ${target_commit}"
  exit 1
fi

# Is the release name sane? Must be a date with patch/rc.
if ! [[ "${release}" =~ ^20[0-9]{6}\.[0-9]+$ ]]; then
  declare -r expected="$(date +%Y%m%d.0)" # Use today's date.
  echo "unexpected release format: ${release}"
  echo "  ... expected like ${expected}"
  exit 1
fi

# Tag the given commit (annotated, to record the committer). Note that the tag
# here is applied as a force, in case the tag already exists and is the same.
# The push will fail in this case (because it is not forced).
declare -r tag="release-${release}"
git tag -f -F "${message_file}" -a "${tag}" "${commit}" && \
  git push origin tag "${tag}"
