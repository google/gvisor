#!/bin/bash

# Copyright 2018 Google LLC
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

# Bash "safe-mode":  Treat command failures as fatal (even those that occur in
# pipes), and treat unset variables as errors.
set -eu -o pipefail

# This file will be generated as a self-extracting shell script in order to
# eliminate the need for any runtime dependencies. The tarball at the end will
# include the go_generics binary, as well as a subdirectory named
# generics_tests. See the BUILD file for more information.
declare -r temp=$(mktemp -d)
function cleanup() {
  rm -rf "${temp}"
}
# trap cleanup EXIT

# Print message in "$1" then exit with status 1.
function die () {
  echo "$1" 1>&2
  exit 1
}

# This prints the line number of __BUNDLE__ below, that should be the last line
# of this script. After that point, the concatenated archive will be the
# contents.
declare -r tgz=`awk '/^__BUNDLE__/ {print NR + 1; exit 0; }' $0`
tail -n+"${tgz}" $0 | tar -xzv -C "${temp}"

# The target for the test.
declare -r binary="$(find ${temp} -type f -a -name go_generics)"
declare -r input_dirs="$(find ${temp} -type d -a -name generics_tests)/*"

# Go through all test cases.
for f in ${input_dirs}; do
  base=$(basename "${f}")

  # Run go_generics on the input file.
  opts=$(head -n 1 ${f}/opts.txt)
  out="${f}/output/generated.go"
  expected="${f}/output/output.go"
  ${binary} ${opts} "-i=${f}/input.go" "-o=${out}" || die "go_generics failed for test case \"${base}\""

  # Compare the outputs.
  diff ${expected} ${out}
  if [ $? -ne 0 ]; then
    echo "Expected:"
    cat ${expected}
    echo "Actual:"
    cat ${out}
    die "Actual output is different from expected for test \"${base}\""
  fi
done

echo "PASS"
exit 0
__BUNDLE__
