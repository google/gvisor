#!/bin/sh

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

set -eu

changelog="$1"
compressed_changelog="$2"
doc_tar="$3"

grep -Eq '^runsc \([0-9][^)]*\) release; urgency=medium$' "${changelog}"
grep -q 'https://github.com/google/gvisor/releases' "${changelog}"
gzip -dc "${compressed_changelog}" | cmp - "${changelog}"
tar -tf "${doc_tar}" | grep -qx 'usr/share/doc/runsc/changelog.Debian.gz'
