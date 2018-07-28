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

# Build everything.
bazel build //...

# Test use this variable to determine what runtime to use.
runtime=runsc_test_$((RANDOM))
sudo -n ./runsc/test/install.sh --runtime ${runtime}

# Run the tests and upload results.
#
# We turn off "-e" flag because we must move the log files even if the test
# fails.
set +e
bazel test --test_output=errors //...
exit_code=${?}

if [[ ${exit_code} -eq 0 ]]; then
  declare -a variations=("" "-kvm" "-hostnet" "-overlay")
  for v in "${variations[@]}"; do
    # image_test is tagged manual
    bazel test --test_output=errors --test_env=RUNSC_RUNTIME=${runtime}${v} //runsc/test/image:image_test
    exit_code=${?}
    if [[ ${exit_code} -ne 0 ]]; then
      break
    fi
  done
fi

# Best effort to uninstall
sudo -n ./runsc/test/install.sh -u --runtime ${runtime}
set -e

# Find and rename all test xml and log files so that Sponge can pick them up.
# XML files must be named sponge_log.xml, and log files must be named
# sponge_log.log. We move all such files into KOKORO_ARTIFACTS_DIR, in a
# subdirectory named with the test name.
for file in $(find -L "bazel-testlogs" -name "test.xml" -o -name "test.log"); do
    newpath=${KOKORO_ARTIFACTS_DIR}/$(dirname ${file})
    extension="${file##*.}"
    mkdir -p "${newpath}" && cp "${file}" "${newpath}/sponge_log.${extension}"
done

exit ${exit_code}
