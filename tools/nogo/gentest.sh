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

set -euo pipefail

if [[ "$#" -lt 2 ]]; then
  echo "usage: $0 <output> <findings...>"
  exit 2
fi
declare violations=0
declare output=$1
shift

# Start the script.
echo "#!/bin/sh" > "${output}"

# Read a list of findings files.
declare filename
declare line
for filename in "$@"; do
  if [[ -z "${filename}" ]]; then
    continue
  fi
  while read -r line; do
    line="${line@Q}"
    violations=$((${violations}+1));
    echo "echo -e '\\033[0;31m${line}\\033[0;31m\\033[0m'" >> "${output}"
  done < "${filename}"
done

# Show violations.
if [[ "${violations}" -eq 0 ]]; then
  echo "echo -e '\\033[0;32mPASS\\033[0;31m\\033[0m'" >> "${output}"
else
  echo "exit 1" >> "${output}"
fi
