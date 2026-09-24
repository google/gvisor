#!/bin/bash

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

# Fails if any source file added since BASE_REF lacks the Apache 2.0 license
# header. Modified, renamed and deleted files are not checked.
#
# Usage: tools/check_license_headers.sh [BASE_REF]

set -euo pipefail

readonly BASE="${1:-origin/master}"

readonly BODY='Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.'

# Year is optional and the holder is unconstrained.
readonly COPYRIGHT='^Copyright ([0-9]{4}(-[0-9]{4})? )?The [A-Za-z0-9_.-]+( [A-Za-z0-9_.-]+)* Authors\.'

readonly HEADER_LINES=40

# Strips comment markers, collapses whitespace, drops blank lines, and folds
# the https form of the Apache URL onto the http one.
normalize() {
  head -n "${HEADER_LINES}" -- "$1" | sed -E \
    -e 's,^[[:space:]]*(//+|#+|/\*+|\*+/|\*+|;+)[[:space:]]*,,' \
    -e 's,[[:space:]]+, ,g' \
    -e 's,^ ,,' \
    -e 's, $,,' \
    -e 's,https://www\.apache\.org,http://www.apache.org,' |
    grep -v '^$' || true
}

# Succeeds if the path must carry a header.
is_checked() {
  case "$1" in
    external/* | images/* | tools/bazeldefs/*) return 1 ;;
  esac
  case "$1" in
    *.c | *.cc | *.go | *.h | *.proto | *.s | *.S) return 0 ;;
    *.mk | *.py | *.sh | Makefile | */Makefile) return 0 ;;
  esac
  return 1
}

if ! git rev-parse --verify --quiet "${BASE}" >/dev/null; then
  echo "error: base ref ${BASE} not found; is it fetched?" >&2
  exit 1
fi

# Buffered so that a git failure aborts instead of reading as an empty list.
added="$(mktemp)"
trap 'rm -f "${added}"' EXIT
if ! git diff --name-only --diff-filter=A -z "${BASE}...HEAD" >"${added}"; then
  echo "error: unable to diff against ${BASE}" >&2
  exit 1
fi

needle="$(printf '%s' "${BODY}" | tr '\n' '|')"
failed=0
checked=0

while IFS= read -r -d '' file; do
  is_checked "${file}" || continue
  [ -f "${file}" ] || continue
  checked=$((checked + 1))

  header="$(normalize "${file}")"

  # Generated files carry whatever their generator emits.
  if grep -qiE 'DO NOT EDIT|@generated' <<<"${header}"; then
    continue
  fi

  if [[ "$(tr '\n' '|' <<<"${header}")" == *"${needle}"* ]] &&
    grep -qE "${COPYRIGHT}" <<<"${header}"; then
    continue
  fi

  if grep -qiE 'copyright|licen[cs]e|SPDX' <<<"${header}"; then
    echo "${file}: invalid Apache 2.0 license header" >&2
  else
    echo "${file}: missing Apache 2.0 license header" >&2
  fi
  failed=$((failed + 1))
done <"${added}"

if [ "${failed}" -ne 0 ]; then
  cat >&2 <<EOF

${failed} newly added file(s) need the standard license boilerplate. Add the
following to the top of each one, adjusting the comment marker to suit the
language:

// Copyright $(date +%Y) The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
EOF
  exit 1
fi

echo "Checked ${checked} newly added file(s); all carry the license header."
