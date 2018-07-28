#!/bin/bash

# Copyright 2018 Google Inc.
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

# Fail on any error.
set -e
# Display commands to stderr.
set -x

# Install the latest version of Bazel.
use_bazel.sh latest

# Log the bazel path and version.
which bazel
bazel version

cd git/repo

# Build runsc.
bazel build //runsc

# Move the runsc binary into "latest" directory, and also a directory with the
# current date.
latest_dir="${KOKORO_ARTIFACTS_DIR}"/latest
today_dir="${KOKORO_ARTIFACTS_DIR}"/"$(date -Idate)"
mkdir -p "${latest_dir}" "${today_dir}"
cp bazel-bin/runsc/linux_amd64_pure_stripped/runsc "${latest_dir}"
sha512sum "${latest_dir}"/runsc | awk '{print $1 "  runsc"}' > "${latest_dir}"/runsc.sha512
cp bazel-bin/runsc/linux_amd64_pure_stripped/runsc "${today_dir}"
sha512sum "${today_dir}"/runsc | awk '{print $1 "  runsc"}' > "${today_dir}"/runsc.sha512
