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

# Backfills fscheckpoint corpus snapshots from published gVisor release
# binaries (e.g., release-20260907.0) into compatibility_testing/.

set -euxo pipefail

if [[ "$#" -lt 1 ]]; then
  echo "Usage: $0 <release-tag> [<release-tag> ...]" >&2
  echo "Example: $0 release-20260907.0 release-20261005.0" >&2
  exit 1
fi

arch="$(uname -m)"
out_root="${FSCHECKPOINT_GENERATE_CORPUS_DIR:-$(pwd)/compatibility_testing}"
tmp_dir="$(mktemp -d -p "$(pwd)" .fscheckpoint_backfill.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT

for tag in "$@"; do
  ver="${tag#release-}"
  date_part="${ver%%.*}"
  runsc_bin="${tmp_dir}/${tag}/runsc"
  url="https://storage.googleapis.com/gvisor/releases/release/${ver}/${arch}/gvisor.tar.bz2"

  echo "Downloading ${tag} (${url})..." >&2
  mkdir -p "${tmp_dir}/${tag}"
  curl -fsSL "$url" | tar -xjf - -C "${tmp_dir}/${tag}"
  chmod -R +x "${tmp_dir}/${tag}"

  commit_ts="$(date -d "${date_part} 00:00:00 UTC" +%s 2>/dev/null || date +%s)"
  out_dir="${out_root}/${date_part}-000000_${tag}"
  mkdir -p "$out_dir"

  GVISOR_SIDECAR_BINARIES_DIR="${tmp_dir}/${tag}/gvisor-bin" \
    make sudo TARGETS=//runsc/container:fscheckpoint_compat_test \
    ARGS="-test.v -test.run=TestFSCheckpointCorpusGenerate -fscheckpoint-generate-dir=${out_dir} -fscheckpoint-runsc-bin=${runsc_bin}"

  if [[ -f "${out_dir}/metadata.json" ]] && command -v jq >/dev/null 2>&1; then
    jq --argjson ts "$commit_ts" --arg hash "$tag" \
      '.commit_timestamp_unix = $ts | .commit_hash = $hash' \
      "${out_dir}/metadata.json" > "${out_dir}/metadata.json.tmp"
    mv "${out_dir}/metadata.json.tmp" "${out_dir}/metadata.json"
  fi
done
