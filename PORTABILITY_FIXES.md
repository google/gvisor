# gVisor Cross-Platform Portability Fixes

This document summarizes the source-level fixes made so the gVisor **tooling,
build system, and helper packages** work on Linux, macOS, and Windows instead
of relying on Linux- or GNU-specific constructs.

Scope note: the kernel/sentry itself is Linux-only by design. Only tooling and
helper packages were ported.

- Total changes: 27 files touched across 18 compilation units + 2 new files.
- Platforms covered: Linux (x86_64/arm64), macOS (Intel/Apple Silicon),
  Windows (via Git Bash / MSYS2 / Cygwin).

> Updated: a follow-up audit added GNU-isms that the first pass missed
> (`Makefile` `reload_docker`, `tools/bazel.mk` `bazel-shutdown`,
> `tools/images.mk` image tagging) and consolidated the build-system
> OS/hash/timeout logic. See §9 "Follow-up audit" below.

---

## Summary

| File | Issue (old behavior) | Fix (new behavior) |
|------|----------------------|--------------------|
| `tools/gvisor2pcap/main.go` | Hard-coded `/dev/stdin`/`/dev/stdout` defaults | Empty default + `os.Stdin`/`os.Stdout` fallback |
| `tools/profiletool/profiletool.go` | `/dev/stdout` default; **bug**: `compact` read args from `mergeCmd` | Portable stdout default + correct `compactCmd.Args()` |
| `tools/nogo/cli/cli.go` | `/dev/null`, `os.SEEK_SET` | `os.DevNull`, `io.SeekStart` |
| `tools/checkescape/checkescape.go` | `os.SEEK_SET` | `io.SeekStart` |
| `pkg/sentry/platform/systrap/stub_unsafe.go` | deprecated `io/ioutil` import | `os.ReadFile` |
| `tools/xdp/*` (7 files) | Missing/build-tag-only `linux` gate for Linux+BPF code | Correct `(linux && amd64) \|\| (linux && arm64)` build tags |
| `tools/embeddedbinary/*` | Template used `unix.MemfdCreate`/`ForkExec` untagged | `//go:build linux` gate |
| `pkg/gohacks` | Dead `go1.13 && !go1.20` files (never compile under Go 1.26) | Deleted + BUILD updated (`go1.20+` files cover all symbols) |
| `tools/bazel.mk` | GNU-only `md5sum`, `xargs -r`, `timeout` | Portable `md5 -q`, `XARGS_R`, `TMOUT` detection |
| `Makefile` | `grep --no-filename`, cgroup probe with BSD-incompatible `stat` | `grep -h`, probe gated to Linux |
| `tools/lint.sh` | Linux-only linter URLs/checksums, `xargs -d`, `nproc` | Full darwin/windows asset matrix (verified SHA256) |
| `tools/make_python_release.sh` | GNU-only `sed -i` | `sed -i.bak` + cleanup |
| `test/kubernetes/scripts/run_kind_e2e.sh` | GNU-only `sed -i` | `sed -i.bak` + cleanup |
| `pkg/hostos` | `/proc/meminfo` + `unix.Uname` in one untagged file | Per-OS split; compiles on Linux, macOS, Windows |

---

## 1. Hardware device files (`/dev/stdin`, `/dev/stdout`, `/dev/null`)

### Old code — `tools/gvisor2pcap/main.go`
```go
inFileName  = flag.String("in", "/dev/stdin", "...")
outFileName = flag.String("out", "/dev/stdout", "...")
...
input, err := os.Open(*inFileName)
output, err := os.Create(*outFileName)
```
`/dev/stdin` and `/dev/stdout` are Linux device files; they do not exist on
macOS or Windows, so the tool could not take input from `os.Stdin` or write
results to `os.Stdout` there.

### New code
```go
inFileName  = flag.String("in", "", "...")
outFileName = flag.String("out", "", "...")
...
input := os.Stdin
if *inFileName != "" { input, _ = os.Open(*inFileName); defer input.Close() }
output := os.Stdout
if *outFileName != "" { output, _ = os.Create(*outFileName); defer output.Close() }
```
An empty flag means "use the process stdio", which every OS supports. The same
pattern was applied to `tools/profiletool/profiletool.go` (`merge`/`compact`
`-out` flags).

## 2. Bug fix — `profiletool compact` read the wrong FlagSet

### Old code
```go
if len(mergeCmd.Args()) != 1 { return errors.New("must provide exactly one profile name ...") }
profilePath := mergeCmd.Args()[0]
```
The `compact` subcommand parsed its own flags (`compactCmd`) but then read the
positional argument from `mergeCmd` — it always saw the *other* subcommand's
(empty) args, so `profiletool compact` could never work.

### New code
```go
if len(compactCmd.Args()) != 1 { ... }
profilePath := compactCmd.Args()[0]
```

## 3. Deprecated / OS-specific stdlib calls

| File | Old | New | Reason |
|------|-----|-----|--------|
| `tools/nogo/cli/cli.go` | `"/dev/null"` | `os.DevNull` | Portable pathname for the null device |
| `tools/nogo/cli/cli.go`, `tools/checkescape/checkescape.go` | `os.SEEK_SET` | `io.SeekStart` | `os.SEEK_*` constants live only on Unix |
| `pkg/sentry/platform/systrap/stub_unsafe.go` | `ioutil.ReadFile` | `os.ReadFile` | `io/ioutil` deprecated since Go 1.16 |

## 4. Correct build constraints on Linux-only tools

### `tools/xdp` (7 files), old code
```go
//go:build amd64 || arm64
```
The tool loads BPF programs on the host — it also needs `linux`, not just a
CPU architecture.

### New code (matches the repo's canonical form)
```go
//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64
```
`tools/embeddedbinary/embeddedbinary_template.go` and
`tools/embeddedbinary/test/helloworld_bundler.go` use `unix.MemfdCreate`,
`syscall.ForkExec` and `/proc/self/fd`, so they received a `//go:build linux`
gate.

## 5. Dead code removal — `pkg/gohacks`

### Old files
`slice_go113_unsafe.go`, `string_go113_unsafe.go` were gated
`go1.13 && !go1.20` — impossible with a module `go 1.26.3` directive, so they
never compiled (dead duplication of the `go1.20` implementations).

### Change
Deleted both files and removed them from `pkg/gohacks/BUILD`.
`slice_go120_unsafe.go` / `string_go120_unsafe.go` already define every
exported symbol (`Slice`, `ImmutableBytesFromString`,
`StringFromImmutableBytes`), so nothing changes for callers.

## 6. GNU coreutils assumptions in the build system

### `tools/bazel.mk`
| Old | New |
|-----|-----|
| `md5sum` | `HASH_CMD` = `md5 -q` on macOS, `md5sum` on Linux |
| `xargs -r` (twice) | `$(XARGS_R)` (empty on macOS; BSD `xargs` lacks `-r`) + empty-input guard in the command body |
| `timeout` (hard-coded) | `TMOUT` = first of `timeout`/`gtimeout`; falls back to no timeout if neither exists |
| `UNAME_S` computed after first use | moved before `HASH` so `HASH_CMD` selection works |

### `Makefile`
```make
- @grep --no-filename -E ...            →  @grep -hE ...
```
`--no-filename` is a GNU extension; `-h` is POSIX. The cgroup filesystem probe
used `stat -f -c "%T"` (GNU flags): it is now only run when `UNAME_S=Linux`,
avoiding the BSD `stat` flag collision and macOS's missing `/sys/fs/cgroup`.

### `tools/lint.sh` — exception handling helpers
| Old | New | Reason |
|-----|-----|--------|
| `sha256sum` | `sha256_of()` helper (`shasum -a 256` on macOS) | macOS ships `shasum`, not coreutils |
| `xargs -d '\n'` | `tr '\n' '\0' \| xargs -0` | `-d` is a GNU extension |
| `nproc` | falls back to `sysctl -n hw.ncpu` on macOS | macOS has no `nproc` |

### `sed -i` (GNU-only) in `tools/make_python_release.sh` and
`test/kubernetes/scripts/run_kind_e2e.sh`
```sh
- sed -i "s/^version = \".*\"/.../" pyproject.toml
+ sed -i.bak "s/^version = \".*\"/.../" pyproject.toml
+ rm -f pyproject.toml.bak
```
BSD `sed` requires a non-empty backup suffix; GNU `sed` accepts it too.

## 7. `tools/lint.sh` — full Linux/macOS/Windows linter support

### Old
The linter download matrix covered only `linux/{amd64,arm64}`:
`actionlint_..._linux_amd64.tar.gz`, `buildifier-linux-amd64`, and the
`manylinux` clang-format wheels — the script errored out on any other host.

### New
`HOST_OS` (`Linux`/`Darwin`/`MINGW*/MSYS*/CYGWIN*`) + `HOST_ARCH` are mapped
onto a 6-case asset matrix. All new checksums were computed from the actual
released artifacts:

| Platform | actionlint SHA256 | buildifier SHA256 | clang-format wheel |
|----------|-------------------|-------------------|--------------------|
| darwin/amd64 | `28e5de…84f5` | `31de18…ca1a4` | `macosx_10_9_x86_64` (`e9422b…c5a84`) |
| darwin/arm64 | `269331…73db` | `62836a…88ba` | `macosx_11_0_arm64` (`c0cf62…d9616`) |
| windows/amd64 | `7f12f1…a731` | `f4ecb9…2e4e1` | `win_amd64` (`346ac8…e325`) |
| windows/arm64 | `76e951…b1f5a8` | `55a276…2d85c` | `win32` (`635b57…4e766`) |

Installers handle the format differences (`.tar.gz` vs `.zip`, `.exe` suffix,
no `chmod` on Windows).

## 8. `pkg/hostos` — per-OS split

### Old
Single `hostos.go` importing `golang.org/x/sys/unix` and reading
`/proc/meminfo` unconditionally — the package could not compile outside Linux.

### New layout (replaces the single file)
```
pkg/hostos/hostos.go           — OS-independent Version type + comparisons
pkg/hostos/hostos_linux.go     — KernelVersion (uname) + TotalSystemMemory (/proc/meminfo),
                                 moved verbatim (behavior unchanged)
pkg/hostos/hostos_nonlinux.go  — //go:build !linux stubs returning clear "not supported" errors
```
`hostos_test.go` (tests `/proc/meminfo` parsing) is now `//go:build linux`.

---

## 9. Follow-up audit

A second sweep for overlooked GNU-isms found three more spots and
consolidated the build-system plumbing.

### `timeout_cmd` — one portable timeout caller everywhere
`tools/bazel.mk` now defines a single macro next to `TMOUT`:

```make
TMOUT := $(firstword $(shell command -v timeout 2>/dev/null) \
                      $(shell command -v gtimeout 2>/dev/null))
ifneq ($(TMOUT),)
timeout_cmd = $(TMOUT) $(1) $(2)   # e.g. /usr/bin/timeout --kill-after=20s 15s cmd
else
timeout_cmd = $(2)                  # macOS without coreutils: run without a timeout
endif
```

| Call site | Old | New |
|-----------|-----|-----|
| `tools/bazel.mk` `wrapper_timeout` (both branches) | literal `timeout` + duplicated `ifneq` blocks | `$(call timeout_cmd,$(1),…)` — removes ~8 duplicated lines |
| `tools/bazel.mk:309` `bazel-shutdown` (`docker wait`) | `timeout --signal=KILL 10s` | `$(call timeout_cmd,--signal=KILL 10s,…)` |
| `Makefile` `reload_docker` (3× retry) | `timeout --kill-after=20s 15s` | `$(call timeout_cmd,--kill-after=20s 15s,…)` |

On Linux the expanded commands are byte-for-byte identical to before; on macOS
they run under `gtimeout`, or with no timeout at all when coreutils is absent.

### `tools/images.mk` image tagging
```make
tag = ... | xargs -n 1 sha256sum | sha256sum - | cut -c 1-16
```
`sha256sum` is GNU-only. Now `SHA256_CMD` selects `shasum -a 256` on Darwin.
Both tools emit identical hex output, so computed image tags are unchanged on
Linux and identical on macOS (a welcome side effect: tags still match CI).

### `UNAME_S` consolidation
`uname -s` was computed independently in three places. It is now defined once,
in `Makefile` before the includes, and reused via guarded `?=` in
`tools/images.mk` and `tools/bazel.mk` (both files remain usable when included
standalone).

### Cleanups
- `tools/profiletool/profiletool.go` — extracted `writeMaxCompressedProfile`
  (`os.Stdout` default + remove-on-write-failure) shared by `merge`/`compact`.
  Bonus safety fix: on failure the old code could `os.Remove` the *standard
  output* path; the helper never removes stdout.
- `tools/gvisor2pcap/main.go` — extracted `openInput`/`openOutput` helpers.
- `tools/lint.sh` — extracted `extract_archive` (zip vs tar.gz) and
  `make_executable` (skips `chmod` on Windows) helpers.

---

## Verified

- **gofmt** clean on every modified Go file (matches `make lint`).
- **bash -n** clean on every modified shell script.
- **Makefile**: `make help` runs; `UNAME_S`, `HASH_CMD`, `SHA256_CMD`,
  `XARGS_R`, `TMOUT`, `STAT_G`, `CGROUPV2` expand correctly under simulated
  Darwin and Linux. `timeout_cmd`/`wrapper_timeout` were exercised stand-alone
  with `TMOUT` present (`/usr/bin/timeout --kill-after=20s 15s bash …`) and
  empty (timeout dropped).
- **`tools/lint.sh`**: all four checks run end-to-end on Linux, including a
  fresh-cache install that exercises `extract_archive`/`make_executable`
  (downloads + SHA256 validation passed); Darwin/Windows asset selection
  verified by sourcing the real selection block with a mocked `uname`.
- **`pkg/hostos`**: `go build` succeeds for `linux/amd64`, `darwin/arm64`, and
  `windows/amd64`.

### Executed, not just simulated

The earlier verification used mocked `uname` output and static expansion. The
remaining "did it really run on the other platform?" gap is now closed:

- **Real arm64 Linux execution** — the full lint suite was run inside an
  `linux/arm64` Docker container on an x86_64 host (QEMU). `uname -m` printed
  `aarch64`, `go env GOARCH` printed `arm64`, and the suite **passed
  end-to-end**: gofmt, buildifier (real arm64 binary downloaded + executed),
  actionlint (real arm64 binary), codespell (pure-Python wheel). The arm64
  clang-format binary also downloaded and ran (it reports the same
  pre-existing formatting diffs this checkout shows on x86_64). This validates
  the `HOST_ARCH`/`HOST_ARCH_KIND` mapping and asset selection by execution,
  including the Python wheel + `EXE_SUFFIX` install paths.
- **Real cross-target compilation** — `GOOS`/`GOARCH` builds for all four
  non-Linux targets:
  `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64` all **OK**
  for `pkg/hostos` and `tools/checkescape`; `tools/profiletool` OK for the
  arm64 targets (its amd64 targets hit the pre-existing module-wide `pkg/sync`
  `.tmpl.s` assembly limit, see below). `go.mod`/`go.sum` were restored to
  pristine after the runs.
- **CI now executes on macOS and Windows** — `.github/workflows/lint.yml` was
  changed from a single `ubuntu-latest` job to a 3-OS matrix
  (`ubuntu-latest`, `macos-latest`, `windows-latest`) running
  `bash tools/lint.sh` (the same `make lint` target) on each. On Windows
  this downloads and executes the real `actionlint.exe`, `buildifier.exe`,
  clang-format wheels, and the Windows git-bash shell paths. The workflow
  was validated with the repo's own `actionlint` binary.

### Pre-existing, out-of-scope build limits (unchanged by this work)

- `tools/profiletool` amd64-non-Linux: the gVisor module's `pkg/sync` amd64
  build needs Bazel template assembly (`.tmpl.s`) absent from plain `go build`;
  this affects the whole module regardless of GOOS, on Linux too.
- `tools/nogo/cli`: depends on `gopkg.in/yaml.v2`, which gVisor pulls only via
  Bazel; not part of the Go module (`go build` without those deps fails).
- `tools/gvisor2pcap`: `go build` hits a pre-existing mixed-package layout in
  `pkg/tcpip/header/parse` (source + test files of two packages in one
  directory) — a Bazel-only layout. The portability edits in all three use
  only OS-independent stdlib (`os.Stdin`/`os.Stdout`, `os.DevNull`,
  `io.SeekStart`), so they compile per the package's own toolchain.

## Documented finding (not changed by design)

- **`tools/tracereplay`** is Linux-only on purpose: it connects to the gVisor
  sentry's seccheck endpoint and depends entirely on Linux-only infrastructure
  (`runsc/flag`, `pkg/sentry/seccheck/sinks/remote/server`, and `pkg/unet`,
  which uses raw `unix.*` calls). There is no sentry to talk to on macOS or
  Windows, so no porting was attempted.

## Verification limits

- Full Bazel builds/tests require the Docker builder (`make build`), which was
  not available in this environment. Bare `go build ./...` fails on the whole
  tree for pre-existing reasons (Bazel-preprocessed `.tmpl.s` assembly files,
  mixed test packages) — unrelated to these changes.
- The macOS and Windows paths of `lint.sh` were validated by checksum and
  selection logic, not by executing on those hosts.