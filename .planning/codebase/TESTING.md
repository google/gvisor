# Testing Patterns

**Analysis Date:** 2026-03-08

## Test Framework

**Build System:** Bazel (not `go test`)

gVisor uses Bazel as its primary build and test system. The repository uses `go_test` Bazel rules (from `@io_bazel_rules_go`). Standard `_test.go` files exist in the full repository but are excluded from this Go module checkout (they are managed by Bazel `BUILD` files, not `go.mod`).

**Runner:**
- Bazel with `@io_bazel_rules_go` rules
- No `go test` configuration (no `go.sum` test deps, no test framework in `go.mod`)
- Tests run via `bazel test //path/to:target`

**Assertion Library:**
- Standard Go `testing` package
- `github.com/google/go-cmp` (v0.6.0, in `go.mod`) for structural comparisons

**Run Commands:**
```bash
bazel test //pkg/seccomp:seccomp_test    # Run specific test
bazel test //runsc/...                    # Run all runsc tests
bazel test //pkg/...                      # Run all pkg tests
```

## Test File Organization

**Location:**
- Co-located with source code (same package directory)
- Standard `_test.go` suffix (managed by Bazel, not present in this checkout)
- Test utilities are checked in as non-test files with special naming:
  - `*_test_util.go` — test helpers used across packages
  - `*_testonly.go` — code only compiled with `check_invariants` build tag

**Naming:**
- Test files: `<subject>_test.go`
- Test utility files: `<subject>_test_util.go` (e.g., `runsc/boot/portforward/portforward_test_util.go`)
- Build-tag-guarded test-only files: `debug_testonly.go`

**Structure:**
```
pkg/seccomp/
├── seccomp.go
├── seccomp_rules.go
├── seccomp_amd64.go
├── seccomp_arm64.go
└── (seccomp_test.go - in Bazel, not in go module checkout)
```

## Test Helpers and Utilities

**Test Stacks/Mocks (checked-in test utilities):**

Test stacks implement production interfaces with simplified behavior for testing:

```go
// pkg/sentry/inet/test_stack.go
var _ Stack = (*TestStack)(nil)

type TestStack struct {
    InterfacesMap     map[int32]Interface
    InterfaceAddrsMap map[int32][]InterfaceAddr
    RouteList         []Route
    SupportsIPv6Flag  bool
    // ...
}

func NewTestStack() *TestStack {
    return &TestStack{
        InterfacesMap:     make(map[int32]Interface),
        InterfaceAddrsMap: make(map[int32][]InterfaceAddr),
    }
}
```

Reference: `pkg/sentry/inet/test_stack.go`

**Mock Endpoints Pattern:**

```go
// runsc/boot/portforward/portforward_test_util.go
type mockEndpoint interface {
    read(n int) ([]byte, error)
    write(buf []byte) (int, error)
}

type portforwarderTestHarness struct {
    app  mockEndpoint
    shim mockEndpoint
}
```

Mocks use VFS embedding for file description mocking:
```go
type mockApplicationFDImpl struct {
    vfs.FileDescriptionDefaultImpl
    vfs.NoLockFD
    vfs.DentryMetadataFileDescriptionImpl
    mu sync.Mutex
    // ...
}
```

Reference: `runsc/boot/portforward/portforward_test_util.go`

**Test-Only Build Tags:**

Code that should only be compiled for testing uses the `check_invariants` build tag:
```go
//go:build check_invariants
// +build check_invariants

package vfs

const checkInvariants = true
```

Reference: `pkg/sentry/vfs/debug_testonly.go`

## Test-Only Configuration

The runtime has explicit test-only flags and configuration fields:

```go
// runsc/config/config.go
TestOnlyAllowRunAsCurrentUserWithoutChroot bool `flag:"TESTONLY-unsafe-nonroot"`
TestOnlyTestNameEnv string `flag:"TESTONLY-test-name-env"`
TestOnlyAFSSyscallPanic bool `flag:"TESTONLY-afs-syscall-panic"`
TestOnlyAutosaveImagePath string `flag:"TESTONLY-autosave-image-path"`
TestOnlyAutosaveResume bool `flag:"TESTONLY-autosave-resume"`
```

These fields are prefixed with `TestOnly` and flags with `TESTONLY-` to make test-only code clearly identifiable.

## Log Integration for Tests

The `pkg/log` package provides `TestEmitter` for integrating gVisor logging with Go's testing framework:

```go
// pkg/log/log.go
type TestLogger interface {
    Logf(format string, v ...any)
}

type TestEmitter struct {
    TestLogger
}
```

Use `log.SetTarget(&log.TestEmitter{t})` in test setup to route gVisor logs through `testing.T.Logf`.

## Mocking

**Framework:** No external mocking framework. Mocks are hand-written.

**Patterns:**
- Interface-based mocking: define interfaces, implement test doubles
- VFS embedding: compose mock file descriptions from `vfs.*Impl` base structs
- Test stacks: full interface implementations with in-memory state (e.g., `TestStack`)
- Compile-time interface assertions: `var _ Interface = (*MockImpl)(nil)`

**What to Mock:**
- Network stacks (`inet.Stack` -> `TestStack`)
- File descriptions (VFS layer -> embed `vfs.FileDescriptionDefaultImpl`)
- Endpoints (network endpoints -> `mockEndpoint`)

**What NOT to Mock:**
- Kernel internals (the sentry kernel is tested via integration/syscall tests)
- Seccomp/BPF (tested via actual filter installation)

## Test Types

**Unit Tests:**
- Package-level tests for utility packages (`pkg/seccomp`, `pkg/bpf`, `pkg/fspath`, etc.)
- Co-located `_test.go` files (in Bazel targets)
- Test individual functions and types in isolation

**Integration Tests (Syscall Tests):**
- gVisor's primary test suite tests Linux syscall compatibility
- Tests run inside the sandbox to verify syscall behavior matches Linux
- Configured via `TESTONLY-*` flags in `runsc/config/config.go`
- Run with `syscall_test_runner` harness

**System Tests:**
- End-to-end container lifecycle tests
- Test `runsc` commands (create, start, exec, delete)
- Verify OCI runtime spec compliance

## Coverage

**Requirements:** No coverage thresholds enforced in the Go module itself. Coverage is tracked via Bazel's coverage tooling.

**Coverage Support:**
```go
// runsc/cli/main.go
if *coverageFD >= 0 {
    f := os.NewFile(uintptr(*coverageFD), "coverage file")
    coverage.EnableReport(f)
}
```

The `pkg/coverage` package provides runtime coverage collection, distinct from Go's standard `-cover` flag.

## Static Analysis Tools

**checklocks (custom):**
- Located at `tools/checklocks/`
- Performs lock analysis using annotations (`+checklocks`, `+checklocksignore`)
- Validates that fields annotated with `+checklocks` are accessed under the correct mutex
- Runs as a `go/analysis` analyzer

**Reference:** `tools/checklocks/checklocks.go`

## Generated Test Infrastructure

**Mutex wrappers (`*_mutex.go`):**
Generated mutex types wrap `sync.Mutex` with lock-order validation via `pkg/sync/locking`. These are used in tests to catch lock ordering violations at runtime.

Example: `pkg/sentry/vfs/virtual_filesystem_mutex.go`

**Reference counter types (`*_refs.go`):**
Generated reference counting implementations include leak detection support. Leak checking mode is configurable (`NoLeakChecking`, `LeaksLogWarning`, `LeaksPanic`).

Example: `pkg/sentry/kernel/fd_table_refs.go`

## Common Test Patterns

**Interface compliance assertion:**
```go
var _ Stack = (*TestStack)(nil)
```

**Table-driven tests (standard Go pattern):**
Used throughout the codebase in Bazel-managed test files.

**Cleanup in tests:**
Use `cleanup.Make` / `cu.Release()` pattern (same as production code):
```go
cu := cleanup.Make(func() { resource.Close() })
defer cu.Clean()
// ... test operations ...
cu.Release()
```

**Build-tag-guarded invariant checking:**
```go
//go:build check_invariants
const checkInvariants = true
```

Production code checks this constant to enable expensive invariant validation only during testing.

## Test Data

**Fixtures/Constants:**
- Test data is typically inline in test files or in dedicated `testdata/` directories (managed by Bazel)
- Test stacks initialize with `make(map[...])` for clean state

**Precompiled Test Data:**
- Seccomp filters can be precompiled and compared in tests
- BPF programs have decode/encode tests

---

*Testing analysis: 2026-03-08*
