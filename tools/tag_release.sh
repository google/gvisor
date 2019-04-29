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

set -euxo pipefail

# Check arguments.
if [ "$#" -ne 2 ]; then
  echo "usage: $0 <commit|revid> <release.rc>"
  exit 1
fi

commit=$1
release=$2

# Is the passed identifier a sha commit?
if ! git show "${commit}" &> /dev/null; then
  # Extract the commit given a piper ID.
  commit=$(git log|grep -E "(^commit |^    PiperOrigin-RevId:)" |grep -B1 "RevId: ${commit}"| head -n1|cut -d" " -f2)
fi
if ! git show "${commit}" &> /dev/null; then
  echo "unknown commit: ${commit}"
  exit 1
fi

# Is the release name sane? Must be a date with patch/rc.
if ! [[ "${release}" =~ ^20[0-9]{6}\.[0-9]+$ ]]; then
  expected=$(date +%Y%m%d.0) # Use today's date.
  echo "unexpected release format: ${release}"
  echo "  ... expected like ${expected}"
  exit 1
fi

# Tag the given commit.
tag="release-${release}"
(git tag "${tag}" "${commit}" && git push origin tag "${tag}") || \
  (git tag -d "${tag}" && false)
