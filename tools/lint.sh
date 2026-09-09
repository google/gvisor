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

case "$(uname -m)" in
  x86_64|amd64)
    declare -r ACTIONLINT_ARCH="amd64"
    declare -r ACTIONLINT_SHA256="023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"
    declare -r BUILDIFIER_ARCH="amd64"
    declare -r BUILDIFIER_SHA256="887377fc64d23a850f4d18a077b5db05b19913f4b99b270d193f3c7334b5a9a7"
    declare -r CLANG_FORMAT_URL="https://files.pythonhosted.org/packages/a6/77/786aa0fc8a75d8ce94966bb33e44c63fec1964cbf343ee862ed6a5be38c1/clang_format-${CLANG_FORMAT_VERSION}-py2.py3-none-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"
    declare -r CLANG_FORMAT_SHA256="7c6bcb7e01ba4f05a4c980fda147b330f7e4833c2aea8c92a0c2df9573ae7afe"
    ;;
  aarch64|arm64)
    declare -r ACTIONLINT_ARCH="arm64"
    declare -r ACTIONLINT_SHA256="401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0"
    declare -r BUILDIFIER_ARCH="arm64"
    declare -r BUILDIFIER_SHA256="947bf6700d708026b2057b09bea09abbc3cafc15d9ecea35bb3885c4b09ccd04"
    declare -r CLANG_FORMAT_URL="https://files.pythonhosted.org/packages/06/60/7c2ff3019599ad985d0a61f74ba8226d538c72485b0e3d25b1899601a9f5/clang_format-${CLANG_FORMAT_VERSION}-py2.py3-none-manylinux_2_27_aarch64.manylinux_2_28_aarch64.whl"
    declare -r CLANG_FORMAT_SHA256="34de32fe53452a07497793d5faf3fd03f7cf8b960b915417471ae81227461a39"
    ;;
  *)
    echo "lint: unsupported architecture $(uname -m)" >&2
    exit 1
    ;;
esac

# FIX is set by --fix; checks that can rewrite files consult it.
declare FIX=0

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
  got="$(sha256sum "${tmp}" | cut -d' ' -f1)"
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
  local -r bin="${CACHE_DIR}/actionlint-${ACTIONLINT_VERSION}"
  if [[ ! -x "${bin}" ]]; then
    local -r tarball="${CACHE_DIR}/actionlint.tar.gz"
    local -r dir="${CACHE_DIR}/actionlint.d"
    fetch "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${ACTIONLINT_ARCH}.tar.gz" \
      "${ACTIONLINT_SHA256}" "${tarball}"
    rm -rf "${dir}" && mkdir -p "${dir}"
    tar -xzf "${tarball}" -C "${dir}"
    mv "${dir}/actionlint" "${bin}"
    rm -rf "${dir}" "${tarball}"
  fi
  echo "${bin}"
}

install_buildifier() {
  local -r bin="${CACHE_DIR}/buildifier-${BUILDIFIER_VERSION}"
  if [[ ! -x "${bin}" ]]; then
    fetch "https://github.com/bazelbuild/buildtools/releases/download/v${BUILDIFIER_VERSION}/buildifier-linux-${BUILDIFIER_ARCH}" \
      "${BUILDIFIER_SHA256}" "${bin}"
    chmod +x "${bin}"
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
  local -r bin="${CACHE_DIR}/clang-format-${CLANG_FORMAT_VERSION}"
  if [[ ! -x "${bin}" ]]; then
    local -r wheel="${CACHE_DIR}/clang-format.whl"
    local -r dir="${CACHE_DIR}/clang-format.d"
    fetch "${CLANG_FORMAT_URL}" "${CLANG_FORMAT_SHA256}" "${wheel}"
    rm -rf "${dir}" && mkdir -p "${dir}"
    unzip -q "${wheel}" -d "${dir}"
    mv "${dir}/clang_format/data/bin/clang-format" "${bin}"
    chmod +x "${bin}"
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
    echo "${unformatted}" | xargs -d '\n' "${gofmt}" -d
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
  local -r jobs="$(nproc 2>/dev/null || echo 1)"
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
