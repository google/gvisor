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

# lint.sh runs gVisor's source-level lint checks. It runs without Bazel or a
# builder container. Deep Go analysis is owned by gVisor nogo.
#
# Usage:
#   tools/lint.sh                     # run every check
#   tools/lint.sh gofmt clang-format  # run only the named checks
#   tools/lint.sh --fix               # rewrite files in place where a check can
#
# Environment:
#   LINT_CACHE_DIR   where to cache downloaded linters
#                    (default: ~/.cache/gvisor/lint)

set -euo pipefail

declare REPO_DIR
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_DIR
cd "${REPO_DIR}"

declare -r CACHE_DIR="${LINT_CACHE_DIR:-${HOME}/.cache/gvisor/lint}"

# Every check, in run order, named as tools/lint.sh accepts it.
declare -ra ALL_CHECKS=(gofmt clang-format buildifier actions spelling)
# Only the formatters can rewrite a file; the rest have no safe autofix.
declare -ra FIXABLE_CHECKS=(gofmt clang-format buildifier)

declare -r ACTIONLINT_VERSION="1.7.7"
declare -r CODESPELL_VERSION="2.3.0"
declare -r CLANG_FORMAT_VERSION="20.1.8"
# Keep in sync with images/default/Dockerfile.
declare -r BUILDIFIER_VERSION="8.5.1"

# The codespell wheel is architecture-independent.
declare -r CODESPELL_URL="https://files.pythonhosted.org/packages/0e/20/b6019add11e84f821184234cea0ad91442373489ef7ccfa3d73a71b908fa/codespell-${CODESPELL_VERSION}-py3-none-any.whl"
declare -r CODESPELL_SHA256="a9c7cef2501c9cfede2110fd6d4e5e62296920efe9abfb84648df866e47f58d1"

# Map the host OS and architecture to the naming used by each linter's release
# assets. Linux, macOS and Windows (Git Bash / MSYS2 / Cygwin) are supported;
# lint.sh runs outside the Bazel container, directly on the host.
declare -r HOST_OS="$(uname -s)"
case "${HOST_OS}" in
  Linux)
    declare -r HOST_OS_KIND="linux"
    declare -r EXE_SUFFIX=""
    ;;
  Darwin)
    declare -r HOST_OS_KIND="darwin"
    declare -r EXE_SUFFIX=""
    ;;
  MINGW*|MSYS*|CYGWIN*)
    declare -r HOST_OS_KIND="windows"
    declare -r EXE_SUFFIX=".exe"
    ;;
  *)
    echo "lint: unsupported operating system ${HOST_OS}" >&2
    exit 1
    ;;
esac

declare -r HOST_ARCH="$(uname -m)"
case "${HOST_ARCH}" in
  x86_64|amd64)
    declare -r HOST_ARCH_KIND="amd64"
    ;;
  aarch64|arm64)
    declare -r HOST_ARCH_KIND="arm64"
    ;;
  *)
    echo "lint: unsupported architecture ${HOST_ARCH}" >&2
    exit 1
    ;;
esac

case "${HOST_OS_KIND}/${HOST_ARCH_KIND}" in
  linux/amd64)
    declare -r ACTIONLINT_SHA256="023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"
    declare -r BUILDIFIER_SHA256="887377fc64d23a850f4d18a077b5db05b19913f4b99b270d193f3c7334b5a9a7"
    declare -r CLANG_FORMAT_URL="https://files.pythonhosted.org/packages/a6/77/786aa0fc8a75d8ce94966bb33e44c63fec1964cbf343ee862ed6a5be38c1/clang_format-${CLANG_FORMAT_VERSION}-py2.py3-none-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"
    declare -r CLANG_FORMAT_SHA256="7c6bcb7e01ba4f05a4c980fda147b330f7e4833c2aea8c92a0c2df9573ae7afe"
    ;;
  linux/arm64)
    declare -r ACTIONLINT_SHA256="401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0"
    declare -r BUILDIFIER_SHA256="947bf6700d708026b2057b09bea09abbc3cafc15d9ecea35bb3885c4b09ccd04"
    declare -r CLANG_FORMAT_URL="https://files.pythonhosted.org/packages/06/60/7c2ff3019599ad985d0a61f74ba8226d538c72485b0e3d25b1899601a9f5/clang_format-${CLANG_FORMAT_VERSION}-py2.py3-none-manylinux_2_27_aarch64.manylinux_2_28_aarch64.whl"
    declare -r CLANG_FORMAT_SHA256="34de32fe53452a07497793d5faf3fd03f7cf8b960b915417471ae81227461a39"
    ;;
  darwin/amd64)
    declare -r ACTIONLINT_SHA256="28e5de5a05fc558474f638323d736d822fff183d2d492f0aecb2b73cc44584f5"
    declare -r BUILDIFIER_SHA256="31de189e1a3fe53aa9e8c8f74a0309c325274ad19793393919e1ca65163ca1a4"
    declare -r CLANG_FORMAT_URL="https://files.pythonhosted.org/packages/4f/cd/6dab2c15bb2f13ad13015fb92eda0b49b3bd866153072e4d9796f7b220e4/clang_format-${CLANG_FORMAT_VERSION}-py2.py3-none-macosx_10_9_x86_64.whl"
    declare -r CLANG_FORMAT_SHA256="e9422bc81b3bea6c0ee773662fbe3bfd8a9479ae70e59008095dfae7001c5a84"
    ;;
  darwin/arm64)
    declare -r ACTIONLINT_SHA256="2693315b9093aeacb4ebd91a993fea54fc215057bf0da2659056b4bc033873db"
    declare -r BUILDIFIER_SHA256="62836a9667fa0db309b0d91e840f0a3f2813a9c8ea3e44b9cd58187c90bc88ba"
    declare -r CLANG_FORMAT_URL="https://files.pythonhosted.org/packages/d8/4c/3efe4fe6910e1e00dcec0c8d9ef715164500f043e9911bdf253370ff917b/clang_format-${CLANG_FORMAT_VERSION}-py2.py3-none-macosx_11_0_arm64.whl"
    declare -r CLANG_FORMAT_SHA256="c0cf62720247a7dd1e2d610816a2f7d7016433f9c2869880cba655449bd09616"
    ;;
  windows/amd64)
    declare -r ACTIONLINT_SHA256="7f12f1801bca3d480d67aaf7774f4c2a6359a3ca8eebe382c95c10c9704aa731"
    declare -r BUILDIFIER_SHA256="f4ecb9c73de2bc38b845d4ee27668f6248c4813a6647db4b4931a7556052e4e1"
    declare -r CLANG_FORMAT_URL="https://files.pythonhosted.org/packages/bd/ee/656287efdf58dccc7a7299fab547fe1313b49ca1ea1607ea475b262d640f/clang_format-${CLANG_FORMAT_VERSION}-py2.py3-none-win_amd64.whl"
    declare -r CLANG_FORMAT_SHA256="346ac8cab571eaba4d6b89dfa30fdbbc512db82a66ab0eeb1763cacc5977e325"
    ;;
  windows/arm64)
    declare -r ACTIONLINT_SHA256="76e9514cfac18e5677aa04f3a89873c981f16a2f2353bb97372a86cd09b1f5a8"
    declare -r BUILDIFIER_SHA256="55a276ad8b1ff46be48bf64e432264034ea69a45aa3914e89c1d1936f5c2d85c"
    declare -r CLANG_FORMAT_URL="https://files.pythonhosted.org/packages/a7/2d/e02502cd8c845f0b3e17c556648fd481aca0d77935adf8684cda5e4293e5/clang_format-${CLANG_FORMAT_VERSION}-py2.py3-none-win32.whl"
    declare -r CLANG_FORMAT_SHA256="635b57361fa3caeb9449aa62584d7cd38fbee81dbf3addd6b1d7c377eb34e766"
    ;;
  *)
    echo "lint: unsupported platform ${HOST_OS_KIND}/${HOST_ARCH_KIND}" >&2
    exit 1
    ;;
esac

# FIX is set by --fix; checks that can rewrite files consult it.
declare FIX=0

# sha256_of prints the hex-encoded sha256 of a file. macOS ships `shasum -a 256`
# instead of the GNU coreutils `sha256sum`; both print "<hash>  <file>".
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# extract_archive extracts archive into dir. .zip files are handled by unzip;
# everything else is treated as .tar.gz.
extract_archive() {
  local -r archive="$1" dir="$2"
  if [[ "${archive}" == *.zip ]]; then
    unzip -q "${archive}" -d "${dir}"
  else
    tar -xzf "${archive}" -C "${dir}"
  fi
}

# make_executable adds +x to a file when running on a platform that uses
# permission bits (Unix-like). Windows uses extension-based dispatch instead.
make_executable() {
  if [[ "${HOST_OS_KIND}" != "windows" ]]; then
    chmod +x "$1"
  fi
}

# fetch <url> <sha256> <output> downloads a file and verifies its checksum,
# leaving <output> in place only if the checksum matches.
fetch() {
  local -r url="$1" want="$2" out="$3"
  local -r tmp="$(mktemp "${out}.XXXXXX")"
  if ! curl --fail --silent --show-error --location --retry 3 \
      --max-time 300 --output "${tmp}" "${url}"; then
    rm -f "${tmp}"
    echo "lint: failed to download ${url}" >&2
    return 1
  fi
  local got
  got="$(sha256_of "${tmp}")"
  if [[ "${got}" != "${want}" ]]; then
    rm -f "${tmp}"
    echo "lint: checksum mismatch for ${url}" >&2
    echo "lint:   want ${want}" >&2
    echo "lint:   got  ${got}" >&2
    return 1
  fi
  mv "${tmp}" "${out}"
}

install_actionlint() {
  local -r bin="${CACHE_DIR}/actionlint-${ACTIONLINT_VERSION}${EXE_SUFFIX}"
  if [[ ! -x "${bin}" ]]; then
    # actionlint ships .tar.gz archives everywhere except Windows, where it
    # publishes a .zip containing an `actionlint.exe`.
    if [[ "${HOST_OS_KIND}" == "windows" ]]; then
      local -r archive_ext="zip"
    else
      local -r archive_ext="tar.gz"
    fi
    local -r archive="${CACHE_DIR}/actionlint.${archive_ext}"
    local -r dir="${CACHE_DIR}/actionlint.d"
    fetch "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_${HOST_OS_KIND}_${HOST_ARCH_KIND}.${archive_ext}" \
      "${ACTIONLINT_SHA256}" "${archive}"
    rm -rf "${dir}" && mkdir -p "${dir}"
    extract_archive "${archive}" "${dir}"
    mv "${dir}/actionlint${EXE_SUFFIX}" "${bin}"
    rm -rf "${dir}" "${archive}"
  fi
  echo "${bin}"
}

install_buildifier() {
  local -r bin="${CACHE_DIR}/buildifier-${BUILDIFIER_VERSION}${EXE_SUFFIX}"
  if [[ ! -x "${bin}" ]]; then
    fetch "https://github.com/bazelbuild/buildtools/releases/download/v${BUILDIFIER_VERSION}/buildifier-${HOST_OS_KIND}-${HOST_ARCH_KIND}${EXE_SUFFIX}" \
      "${BUILDIFIER_SHA256}" "${bin}"
    make_executable "${bin}"
  fi
  echo "${bin}"
}

install_codespell() {
  local -r dir="${CACHE_DIR}/codespell-${CODESPELL_VERSION}"
  if [[ ! -d "${dir}" ]]; then
    local -r wheel="${CACHE_DIR}/codespell.whl"
    fetch "${CODESPELL_URL}" "${CODESPELL_SHA256}" "${wheel}"
    rm -rf "${dir}.tmp" && mkdir -p "${dir}.tmp"
    unzip -q "${wheel}" -d "${dir}.tmp"
    mv "${dir}.tmp" "${dir}"
    rm -f "${wheel}"
  fi
  echo "${dir}"
}

install_clang_format() {
  local -r bin="${CACHE_DIR}/clang-format-${CLANG_FORMAT_VERSION}${EXE_SUFFIX}"
  if [[ ! -x "${bin}" ]]; then
    local -r wheel="${CACHE_DIR}/clang-format.whl"
    local -r dir="${CACHE_DIR}/clang-format.d"
    fetch "${CLANG_FORMAT_URL}" "${CLANG_FORMAT_SHA256}" "${wheel}"
    rm -rf "${dir}" && mkdir -p "${dir}"
    unzip -q "${wheel}" -d "${dir}"
    mv "${dir}/clang_format/data/bin/clang-format${EXE_SUFFIX}" "${bin}"
    make_executable "${bin}"
    rm -rf "${dir}" "${wheel}"
  fi
  echo "${bin}"
}

find_gofmt() {
  if command -v gofmt >/dev/null 2>&1; then
    command -v gofmt
    return 0
  fi
  if command -v go >/dev/null 2>&1; then
    local -r candidate="$(go env GOROOT)/bin/gofmt"
    if [[ -x "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  fi
  echo "lint: gofmt not found; install Go or put gofmt on PATH" >&2
  return 1
}

# Only tracked files, to skip bazel-* symlinks and other build output.
go_files() { git ls-files -z -- '*.go'; }
doc_files() { git ls-files -z -- '*.md' '*.html'; }
cc_files() { git ls-files -z -- '*.c' '*.cc' '*.h'; }
bazel_files() {
  git ls-files -z -- 'BUILD' '*/BUILD' '*.bzl' 'WORKSPACE' 'MODULE.bazel'
}

declare -a FAILED=()
declare -a PASSED=()

# report <name> <status> records a check result for the final summary.
report() {
  if [[ "$2" -eq 0 ]]; then
    PASSED+=("$1")
  else
    FAILED+=("$1")
  fi
}

check_gofmt() {
  local gofmt
  gofmt="$(find_gofmt)" || return 1
  if [[ "${FIX}" -eq 1 ]]; then
    go_files | xargs -0 "${gofmt}" -w -l
    return 0
  fi
  local unformatted
  unformatted="$(go_files | xargs -0 "${gofmt}" -l)"
  if [[ -n "${unformatted}" ]]; then
    # -d shows what would change; -l alone only names the files.
    # Use NUL-delimited input instead of `xargs -d` (a GNU extension).
    printf '%s' "${unformatted}" | tr '\n' '\0' | xargs -0 "${gofmt}" -d
    echo
    echo "Run \`make lint-fix\` to reformat these files." >&2
    return 1
  fi
}

# The style lives in //.clang-format; clang-format finds it by walking up
# from each file, so no style is passed here.
check_clang_format() {
  # Without the config, clang-format silently falls back to LLVM style.
  if [[ ! -f "${REPO_DIR}/.clang-format" ]]; then
    echo "lint: .clang-format is missing from the repository root" >&2
    return 1
  fi
  local clang_format
  clang_format="$(install_clang_format)"
  # clang-format is single-threaded and each file is independent.
  local jobs
  if [[ "${HOST_OS_KIND}" == "darwin" ]]; then
    # macOS has no GNU coreutils; nproc lives in Homebrew's coreutils.
    jobs="$(sysctl -n hw.ncpu 2>/dev/null || echo 1)"
  else
    jobs="$(nproc 2>/dev/null || echo 1)"
  fi
  local -r jobs="${jobs}"
  if [[ "${FIX}" -eq 1 ]]; then
    cc_files | xargs -0 -P "${jobs}" -n 32 "${clang_format}" -i
    return 0
  fi
  # --dry-run reports one diagnostic per hunk; collapse it to a file list.
  local warnings status=0
  warnings="$(cc_files |
    xargs -0 -P "${jobs}" -n 32 "${clang_format}" --dry-run -Werror 2>&1)" ||
    status=$?
  if [[ "${status}" -ne 0 ]]; then
    # -Werror reports these as "error:" rather than "warning:".
    local file
    while IFS= read -r file; do
      [[ -n "${file}" ]] || continue
      diff -u --label "${file}" --label "${file} (formatted)" \
        "${file}" <("${clang_format}" "${file}") || true
    done < <(printf '%s\n' "${warnings}" |
      sed -n 's/^\(.*\):[0-9]\+:[0-9]\+: \(warning\|error\): .*/\1/p' | sort -u)
    echo
    echo "Run \`make lint-fix\` to reformat these files." >&2
    return 1
  fi
}

# Formatting only. buildifier --lint reports semantic issues (native rule
# loads, duplicated names) that are out of scope for a formatting check.
check_buildifier() {
  local buildifier
  buildifier="$(install_buildifier)"
  if [[ "${FIX}" -eq 1 ]]; then
    bazel_files | xargs -0 "${buildifier}" --mode=fix
    return 0
  fi
  local unformatted
  unformatted="$(bazel_files | xargs -0 "${buildifier}" --mode=check 2>&1 |
    sed -n 's/^\(.*\) # reformat$/\1/p')"
  if [[ -n "${unformatted}" ]]; then
    local file
    while IFS= read -r file; do
      # -path lets buildifier infer the file type from stdin, so the diff
      # matches what --mode=fix would write.
      diff -u --label "${file}" --label "${file} (formatted)" \
        "${file}" <("${buildifier}" -path="${file}" < "${file}") || true
    done <<< "${unformatted}"
    echo
    echo "Run \`make lint-fix\` to reformat these files." >&2
    return 1
  fi
}

check_actions() {
  local actionlint
  actionlint="$(install_actionlint)"
  # Empty values stop actionlint picking up external checkers from PATH.
  "${actionlint}" -no-color -oneline -shellcheck= -pyflakes=
}

check_spelling() {
  local codespell_dir
  codespell_dir="$(install_codespell)"
  # Source is included, so identifiers codespell reads as prose (offsetP,
  # FillIn, ...) need entries in tools/.codespellrc.
  { doc_files; go_files; cc_files; } |
    PYTHONPATH="${codespell_dir}" xargs -0 python3 -m codespell_lib \
      --config "${REPO_DIR}/tools/.codespellrc"
}

contains() {
  local -r needle="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "${item}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

run_check() {
  local -r name="$1" fn="$2" desc="$3"
  echo "==> ${desc}" >&2
  local status=0
  "${fn}" || status=$?
  report "${name}" "${status}"
}

main() {
  mkdir -p "${CACHE_DIR}"

  local -a args=()
  local arg
  for arg in "$@"; do
    case "${arg}" in
      --fix) FIX=1 ;;
      *)     args+=("${arg}") ;;
    esac
  done

  local -a checks=("${args[@]+"${args[@]}"}")
  if [[ "${#checks[@]}" -eq 0 ]]; then
    checks=("${ALL_CHECKS[@]}")
  fi

  local c
  for c in "${checks[@]}"; do
    if ! contains "${c}" "${ALL_CHECKS[@]}"; then
      echo "lint: unknown check '${c}'" >&2
      echo "lint: known checks: ${ALL_CHECKS[*]}" >&2
      exit 1
    fi
  done

  if [[ "${FIX}" -eq 1 ]]; then
    local -a fixable=()
    for c in "${checks[@]}"; do
      if contains "${c}" "${FIXABLE_CHECKS[@]}"; then
        fixable+=("${c}")
      fi
    done
    checks=("${fixable[@]+"${fixable[@]}"}")
    if [[ "${#checks[@]}" -eq 0 ]]; then
      echo "lint: --fix applies only to ${FIXABLE_CHECKS[*]}" >&2
      exit 1
    fi
  fi

  local check
  for check in "${checks[@]}"; do
    case "${check}" in
      gofmt)        run_check gofmt check_gofmt "gofmt" ;;
      clang-format) run_check clang-format check_clang_format "clang-format" ;;
      buildifier)   run_check buildifier check_buildifier "buildifier" ;;
      actions)      run_check actions check_actions "actionlint" ;;
      spelling)     run_check spelling check_spelling "codespell" ;;
    esac
  done

  echo "==> Lint summary" >&2
  local name
  for name in "${PASSED[@]+"${PASSED[@]}"}"; do
    echo "  PASS  ${name}" >&2
  done
  for name in "${FAILED[@]+"${FAILED[@]}"}"; do
    echo "  FAIL  ${name}" >&2
  done
  if [[ "${#FAILED[@]}" -gt 0 ]]; then
    echo >&2
    echo "lint: ${#FAILED[@]} check(s) failed." >&2
    exit 1
  fi
  echo >&2
  echo "lint: all checks passed." >&2
}

main "$@"
