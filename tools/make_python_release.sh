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

set -xeuo pipefail

usage() {
  echo "usage: $0 <command> [args...]" >&2
  echo "Commands:" >&2
  echo "  build <dest-dir> [release-name]" >&2
  echo "  upload-wheel <target-dir>" >&2
  echo "  all <dest-dir> <target-dir> [release-name]" >&2
  exit 1
}

# get_next_ar_version queries Artifact Registry for today's gvisor versions
# and returns YYYY.MM.DD.<max_rev + 1>, or YYYY.MM.DD.0 if none exist.
get_next_ar_version() {
  local -r today="$(date +%Y.%m.%d)"
  local versions=""

  echo "=== [Version Discovery] Checking Artifact Registry for today's versions (${today}) ===" >&2

  # Query AR via gcloud CLI
  if command -v gcloud >/dev/null 2>&1; then
    echo "Querying versions via: gcloud artifacts versions list --package=gvisor --repository=gvisor--pypi --location=us --project=oss-exit-gate-prod" >&2
    versions=$(gcloud artifacts versions list \
      --package=gvisor \
      --repository=gvisor--pypi \
      --location=us \
      --project=oss-exit-gate-prod \
      --format="value(version)" 2>/dev/null || true)
  fi

  if [[ -n "${versions}" ]]; then
    echo "Found existing versions in Artifact Registry:" >&2
    echo "${versions}" >&2
  else
    echo "No existing versions found in Artifact Registry for today (${today})." >&2
  fi

  # Find the highest revision for today
  local max_rev=""
  if [[ -n "${versions}" ]]; then
    max_rev=$(echo "${versions}" | grep -E "^${today}\.[0-9]+$" | sed "s/^${today}\.//" | sort -n | tail -n 1)
  fi

  if [[ -n "${max_rev}" ]]; then
    local -r next_rev=$((max_rev + 1))
    echo "Highest existing revision: ${max_rev}. Next revision: ${next_rev}." >&2
    echo "${today}.${next_rev}"
  else
    echo "Starting at revision 0 for today: ${today}.0" >&2
    echo "${today}.0"
  fi
}

# update_version converts release-YYYYMMDD.x to PEP 440 CalVer format YYYY.MM.DD.x
# or resolves auto version from AR, and updates pyproject.toml in-place.
update_version() {
  local -r release_name="${1:-}"
  local wheel_version=""

  echo "=== [Version Injection] Updating pyproject.toml version ==="
  if [[ "${release_name}" == "auto" ]] || [[ -z "${release_name}" ]]; then
    echo "Resolving next dynamic version from Artifact Registry..."
    wheel_version=$(get_next_ar_version)
  elif [[ "${release_name}" =~ ^([0-9]{4})\.([0-9]{2})\.([0-9]{2})\.(.*)$ ]]; then
    # Already in YYYY.MM.DD.x format
    wheel_version="${release_name}"
  else
    # Convert release-YYYYMMDD.x or YYYYMMDD.x to YYYY.MM.DD.x
    wheel_version=$(echo "${release_name#release-}" | sed -E 's/^([0-9]{4})([0-9]{2})([0-9]{2})\.(.*)$/\1.\2.\3.\4/')
  fi

  if [[ -n "${wheel_version}" ]]; then
    echo "Updating pyproject.toml version to: ${wheel_version}"
    sed -i "s/^version = \".*\"/version = \"${wheel_version}\"/" pyproject.toml
    echo "pyproject.toml version is now:"
    grep "^version = " pyproject.toml || true
  fi
}

# build_wheel_sdist builds Python SandboxExec wheel and sdist archives and copies them to dest-dir.
build_wheel_sdist() {
  local -r dest_dir="$1"
  local -r release_name="${2:-}"

  echo "=== [Build] Building Python SandboxExec Wheel & SDist ==="
  mkdir -p "${dest_dir}"
  local -r abs_dest_dir="$(cd "${dest_dir}" && pwd)"
  cd "$(dirname "$0")/../sandboxexec/sandbox/python"
  echo "Working directory: $(pwd)"
  echo "Target destination directory: ${abs_dest_dir}"

  update_version "${release_name}"

  # Build wheel and sdist (with fallback to --no-isolation or uv build)
  echo "Building distribution packages..."
  if python3 -m build 2>/dev/null; then
    echo "Successfully built wheel and sdist with python3 -m build."
  elif python3 -m build --no-isolation 2>/dev/null; then
    echo "Successfully built wheel and sdist with python3 -m build --no-isolation."
  elif command -v uv >/dev/null 2>&1; then
    echo "python3 -m build not available, building with uv build..."
    uv build
  else
    echo "ERROR: Neither python3 -m build nor uv build found to build Python artifacts." >&2
    return 1
  fi

  echo "Generated artifacts in dist/:"
  ls -lh dist/

  echo "Copying artifacts to ${abs_dest_dir}..."
  cp -f dist/*.whl "${abs_dest_dir}/"
  cp -f dist/*.tar.gz "${abs_dest_dir}/"

  echo "Staged Python artifacts in ${abs_dest_dir}:"
  ls -lh "${abs_dest_dir}"
  echo "=== [Build] Python build complete! ==="
}

# ensure_twine_prerequisites checks if twine is available on the system.
# If missing, it installs python3-pip, keyring, keyrings.google-artifactregistry-auth,
# and twine>=5.0.0.
ensure_twine_prerequisites() {
  export PATH="${HOME}/.local/bin:/usr/local/bin:${PATH}"

  if command -v twine >/dev/null 2>&1 || python3 -c "import twine" >/dev/null 2>&1; then
    return 0
  fi

  echo "=== [Bootstrap] twine not found on PATH. Installing publishing prerequisites... ===" >&2
  if ! command -v pip3 >/dev/null 2>&1; then
    echo "pip3 not found. Attempting to install python3-pip..." >&2
    if command -v sudo >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update && sudo apt-get install -y python3-pip
    elif command -v apt-get >/dev/null 2>&1; then
      apt-get update && apt-get install -y python3-pip
    fi
  fi

  if command -v pip3 >/dev/null 2>&1; then
    echo "Installing keyring, keyrings.google-artifactregistry-auth, and twine..." >&2
    pip3 install --quiet --no-cache-dir keyring keyrings.google-artifactregistry-auth "twine>=5.0.0" 2>/dev/null || \
      sudo pip3 install --quiet --no-cache-dir keyring keyrings.google-artifactregistry-auth "twine>=5.0.0" 2>/dev/null || \
      pip3 install --quiet --user --no-cache-dir keyring keyrings.google-artifactregistry-auth "twine>=5.0.0" 2>/dev/null || true
  elif command -v pip >/dev/null 2>&1; then
    pip install --quiet --no-cache-dir keyring keyrings.google-artifactregistry-auth "twine>=5.0.0" 2>/dev/null || true
  fi

  export PATH="${HOME}/.local/bin:/usr/local/bin:${PATH}"
}

# upload_to_ar uploads staged Python wheel and sdist files to OSS Exit Gate Artifact Registry.
upload_to_ar() {
  local -r target_dir="$1"

  ensure_twine_prerequisites

  echo "=== [Upload] Uploading Python artifacts to OSS Exit Gate Artifact Registry ==="
  if [[ ! -d "${target_dir}" ]]; then
    echo "ERROR: Target directory ${target_dir} does not exist." >&2
    return 1
  fi

  local -r abs_target_dir="$(cd "${target_dir}" && pwd)"
  echo "Inspecting artifacts in ${abs_target_dir}..."
  ls -lh "${abs_target_dir}"

  local whl_count tar_count
  whl_count=$(find "${abs_target_dir}" -maxdepth 1 -name '*.whl' 2>/dev/null | wc -l)
  tar_count=$(find "${abs_target_dir}" -maxdepth 1 -name '*.tar.gz' 2>/dev/null | wc -l)
  if [[ "${whl_count}" -eq 0 ]] && [[ "${tar_count}" -eq 0 ]]; then
    echo "ERROR: No .whl or .tar.gz files found in ${abs_target_dir}." >&2
    return 1
  fi

  echo "Found ${whl_count} wheel(s) and ${tar_count} source distribution(s) to upload."
  echo "Publishing artifacts to https://us-python.pkg.dev/oss-exit-gate-prod/gvisor--pypi via twine..."
  if command -v twine >/dev/null 2>&1; then
    echo "Using twine upload..."
    twine upload \
      --repository-url https://us-python.pkg.dev/oss-exit-gate-prod/gvisor--pypi \
      "${abs_target_dir}"/*.whl "${abs_target_dir}"/*.tar.gz
  elif python3 -c "import twine" >/dev/null 2>&1; then
    echo "Using python3 -m twine upload..."
    python3 -m twine upload \
      --repository-url https://us-python.pkg.dev/oss-exit-gate-prod/gvisor--pypi \
      "${abs_target_dir}"/*.whl "${abs_target_dir}"/*.tar.gz
  else
    echo "ERROR: twine not found to publish Python artifacts." >&2
    return 1
  fi

  echo "=== [Upload] Successfully uploaded all artifacts to Artifact Registry! ==="
}

main() {
  if [[ "$#" -lt 1 ]]; then
    usage
  fi

  local -r cmd="$1"
  shift

  case "${cmd}" in
    build)
      if [[ "$#" -lt 1 ]]; then
        usage
      fi
      build_wheel_sdist "$1" "${2:-}"
      ;;
    upload-wheel)
      if [[ "$#" -lt 1 ]]; then
        usage
      fi
      upload_to_ar "$1"
      ;;
    all)
      if [[ "$#" -lt 2 ]]; then
        usage
      fi
      build_wheel_sdist "$1" "${3:-}"
      upload_to_ar "$2"
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
