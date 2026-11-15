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

set -euxo pipefail

readonly REPO_URL="https://github.com/google/gvisor.git"
readonly CORPUS_BRANCH="fscheckpoint-compat-testing"

# Prunes compatibility_testing/ snapshots:
# - Deletes snapshots older than 380 days (~12.5 months, leaving buffer for the
#   12-month compatibility test bucket).
# - Keeps all snapshots younger than 24 hours (plus keep_dir from this run).
# - Within the 380-day window, keeps the earliest snapshot per Monday-Sunday
#   ISO workweek (%G-W%V) AND at least one snapshot per distinct
#   manifest_version (so multiple version bumps in one week are never lost).
prune_snapshots() {
  local keep_dir="$1"
  [[ -d compatibility_testing ]] || return 0

  local now_ts
  now_ts="$(date -u +%s)"
  local recent_cutoff=$((now_ts - 86400))
  local max_age_cutoff=$((now_ts - 380 * 86400))

  local entries=""
  local dir dir_name ts ver
  for dir in compatibility_testing/*/; do
    [[ -d "${dir}" ]] || continue
    dir_name="$(basename "${dir}")"
    ts=0
    ver=0
    if [[ -f "${dir}metadata.json" ]]; then
      read -r ts ver < <(
        jq -r '[(.commit_timestamp_unix // 0), (.manifest_version // 0)] | @tsv' \
          "${dir}metadata.json" 2>/dev/null || echo "0 0"
      ) || true
    fi
    [[ "${ts}" =~ ^[0-9]+$ ]] || ts=0
    [[ "${ver}" =~ ^[0-9]+$ ]] || ver=0
    if (( ts == 0 )); then
      ts="$(date -u -d "${dir_name%%-*}" +%s 2>/dev/null || echo 0)"
      [[ "${ts}" =~ ^[0-9]+$ ]] || ts=0
    fi
    entries+="${ts} ${ver} ${dir_name}"$'\n'
  done
  [[ -n "${entries}" ]] || return 0

  declare -A seen_week=()
  declare -A seen_version=()
  local week_key keep
  while read -r ts ver dir_name; do
    [[ -n "${dir_name}" ]] || continue
    if [[ "${dir_name}" == "${keep_dir}" ]]; then
      if (( ts > 0 )); then
        week_key="$(date -u -d "@${ts}" +%G-W%V)"
        seen_week["${week_key}"]=1
      fi
      if (( ver > 0 )); then
        seen_version["${ver}"]=1
      fi
      continue
    fi
    if (( ts > 0 && ts < max_age_cutoff )); then
      echo "Pruning snapshot older than 380 days: compatibility_testing/${dir_name}" >&2
      rm -rf "compatibility_testing/${dir_name}"
      continue
    fi
    keep=0
    if (( ts > 0 )); then
      week_key="$(date -u -d "@${ts}" +%G-W%V)"
      if [[ -z "${seen_week["${week_key}"]:-}" ]]; then
        seen_week["${week_key}"]=1
        keep=1
      fi
    fi
    if (( ver > 0 )) && [[ -z "${seen_version["${ver}"]:-}" ]]; then
      seen_version["${ver}"]=1
      keep=1
    fi
    if (( keep )); then
      continue
    fi
    if (( ts > 0 && ts < recent_cutoff )); then
      echo "Pruning non-weekly snapshot older than 24h: compatibility_testing/${dir_name}" >&2
      rm -rf "compatibility_testing/${dir_name}"
    fi
  done < <(printf '%s' "${entries}" | LC_ALL=C sort -k1,1n -k3,3)
}

# GitHub CLI authentication.
if [[ -f "${HOME}/.github-token" ]] && command -v gh >/dev/null 2>&1; then
  gh auth login --with-token < "${HOME}/.github-token" || true
  gh auth setup-git || true
fi

# Fetch master and record its SHA for snapshot generation.
git fetch "${REPO_URL}" master
master_sha="$(git rev-parse FETCH_HEAD)"
head_hash="$(git rev-parse --short=8 "${master_sha}")"

if git ls-remote --exit-code --heads "${REPO_URL}" "refs/heads/${CORPUS_BRANCH}" >/dev/null 2>&1; then
  git fetch "${REPO_URL}" "refs/heads/${CORPUS_BRANCH}"
  if git ls-tree --name-only FETCH_HEAD:compatibility_testing 2>/dev/null | grep -c "_${head_hash}$" >/dev/null; then
    echo "Checkpoint for commit ${head_hash} already exists on ${CORPUS_BRANCH}, skipping." >&2
    exit 0
  fi
fi

# Checkout master_sha so HEAD has master's commit hash and timestamp during generation.
git checkout --detach "${master_sha}"

staging_dir="$(mktemp -d -p "$(pwd)" .fscheckpoint_staging.XXXXXX)"
trap 'rm -rf "${staging_dir}"' EXIT

# Build runsc at master HEAD and generate corpus snapshot once into staging_dir.
make fscheckpoint-corpus-generate FSCHECKPOINT_GENERATE_CORPUS_DIR="${staging_dir}"

shopt -s nullglob
staging_entries=("${staging_dir}"/*/)
shopt -u nullglob
if (( ${#staging_entries[@]} != 1 )); then
  echo "Expected 1 generated snapshot in ${staging_dir}, found ${#staging_entries[@]}" >&2
  exit 1
fi
generated_dir="${staging_entries[0]%/}"
generated_dir_name="$(basename "${generated_dir}")"

export GIT_AUTHOR_NAME=gvisor-bot
export GIT_AUTHOR_EMAIL=gvisor-bot@google.com
export GIT_COMMITTER_NAME=gvisor-bot
export GIT_COMMITTER_EMAIL=gvisor-bot@google.com

# Assemble a single squashed corpus commit on top of master and push with CAS retry.
pushed=0
for attempt in 1 2 3 4 5; do
  git fetch "${REPO_URL}" master
  base_master_sha="$(git rev-parse FETCH_HEAD)"

  remote_corpus_sha=""
  if git ls-remote --exit-code --heads "${REPO_URL}" "refs/heads/${CORPUS_BRANCH}" >/dev/null 2>&1; then
    git fetch "${REPO_URL}" "refs/heads/${CORPUS_BRANCH}"
    remote_corpus_sha="$(git rev-parse FETCH_HEAD)"
    if git ls-tree --name-only "${remote_corpus_sha}:compatibility_testing" 2>/dev/null | grep -c "_${head_hash}$" >/dev/null; then
      echo "Checkpoint for commit ${head_hash} already exists on ${CORPUS_BRANCH}, skipping." >&2
      exit 0
    fi
  fi

  git checkout -f -B "${CORPUS_BRANCH}" "${base_master_sha}"
  rm -rf compatibility_testing
  if [[ -n "${remote_corpus_sha}" ]] && \
      git cat-file -e "${remote_corpus_sha}:compatibility_testing" 2>/dev/null; then
    git checkout "${remote_corpus_sha}" -- compatibility_testing
  fi

  mkdir -p compatibility_testing
  rm -rf "compatibility_testing/${generated_dir_name}"
  cp -r "${generated_dir}" compatibility_testing/
  prune_snapshots "${generated_dir_name}"

  git add -A compatibility_testing
  if [[ -n "${remote_corpus_sha}" ]] && \
      git diff --staged --quiet "${remote_corpus_sha}" -- compatibility_testing; then
    echo "No changes to compatibility_testing corpus; skipping commit." >&2
    exit 0
  fi

  git status
  today="$(date -u +"%Y-%m-%d")"
  git commit -m "Update fscheckpoint compatibility corpus (${today}, commit ${head_hash})."

  if git push --force-with-lease="refs/heads/${CORPUS_BRANCH}:${remote_corpus_sha}" \
      "${REPO_URL}" "HEAD:refs/heads/${CORPUS_BRANCH}"; then
    pushed=1
    break
  fi
  echo "Push attempt ${attempt} failed due to concurrent update; retrying..." >&2
  sleep 2
done

if (( ! pushed )); then
  echo "Failed to push ${CORPUS_BRANCH} after multiple attempts." >&2
  exit 1
fi

# Prune old git objects to keep branch storage compact.
git gc --prune=now --quiet || true

echo "fscheckpoint compatibility corpus updated and pushed to ${CORPUS_BRANCH}." >&2
