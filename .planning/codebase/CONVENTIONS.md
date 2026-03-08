# Coding Conventions

**Analysis Date:** 2026-03-08

## License Header

Every `.go` file begins with the Apache 2.0 license header (or occasionally BSD-style for sync-related packages):

```go
// Copyright YYYY The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// ...
```

The year reflects the file creation date.

## Package Documentation

Every package has a `// Package <name> ...` comment on the `package` declaration. Use a descriptive sentence explaining the package's purpose.

```go
// Package cleanup provides utilities to clean "stuff" on defers.
package cleanup
```

Reference: `pkg/cleanup/cleanup.go`, `pkg/log/log.go`, `runsc/container/container.go`

## Naming Patterns

**Files:**
- `snake_case.go` for all source files
- Architecture-specific files use `_amd64` / `_arm64` suffix: `ptrace_amd64.go`, `ptrace_arm64.go`
- Platform/OS-specific files use `_linux` suffix: `aio_linux_unsafe.go`
- Files containing `unsafe` operations use `_unsafe` suffix: `view_unsafe.go`, `bpf_unsafe.go`
- Auto-generated files use `_state_autogen.go`, `_abi_autogen_unsafe.go` suffixes
- Generated mutex wrappers use `_mutex.go` suffix: `virtual_filesystem_mutex.go`
- Generated reference counter types use `_refs.go` suffix: `fd_table_refs.go`
- Test utility files use `_test_util.go` or `_testonly.go` suffix (build-tag guarded)
- Avoid test file suffix `_test.go` in checked-in code (tests live in separate Bazel test targets, not in this Go module checkout)

**Functions/Methods:**
- Standard Go camelCase: `validateID`, `controlSocketName`, `createControlSocket`
- Exported functions use PascalCase: `Install`, `BuildProgram`, `NewTestStack`
- Interface method implementations always add a comment: `// Method implements Interface.`
  ```go
  // Name implements subcommands.Command.Name.
  func (*Exec) Name() string { return "exec" }
  ```
- Constructors use `New` prefix: `New(...)`, `NewTestStack()`, `NewFilePayload(...)`
- Unexported helper methods use descriptive verb-first names: `incRLimitNProc`, `decRLimitNProc`

**Variables:**
- Package-level sentinel errors use `Err` prefix or all-caps errno names:
  ```go
  ErrNameInUse = errors.New("metric name already in use")
  EPERM        = errors.New(errno.EPERM, "operation not permitted")
  ```
- Constants use either camelCase (unexported) or PascalCase (exported):
  ```go
  const skipOneInst = 1                    // unexported
  const InvalidFDID FDID = 0              // exported
  ```

**Types:**
- Exported struct types use PascalCase: `Container`, `Sandbox`, `Config`, `Loader`
- Unexported struct types use camelCase: `containerInfo`, `mountPromise`
- Enum-like types use `iota` pattern with a descriptive type name:
  ```go
  type ContainerRuntimeState int
  const (
      RuntimeStateInvalid ContainerRuntimeState = iota
      RuntimeStateCreating
      RuntimeStateRunning
      RuntimeStateStopped
  )
  ```
- Interface types typically describe the capability: `Emitter`, `Blocker`, `RefCounter`, `ValueMatcher`

**Packages:**
- All lowercase, single-word where possible: `cleanup`, `seccomp`, `waiter`, `log`
- Compound names without separators: `atomicbitops`, `hostarch`, `linuxerr`, `fsutil`

## Code Style

**Formatting:**
- Standard `gofmt` formatting
- No additional formatting tools configured in the repository root
- Tabs for indentation (Go standard)

**Linting:**
- Custom static analysis tool `checklocks` at `tools/checklocks/` performs lock analysis
- Uses `+checklocks` annotations on struct fields to enforce mutex discipline
- Uses `+checklocksignore` to suppress false positives in generated code and known-safe patterns

## Import Organization

**Order (three groups separated by blank lines):**
1. Standard library imports
2. Third-party imports (github.com, golang.org/x, google.golang.org, k8s.io)
3. Internal imports (gvisor.dev/gvisor/...)

**Import aliasing patterns:**
- Standard library conflicts: `gocontext "context"`, `gtime "time"`, `stdlog "log"`
- OCI specs always aliased: `specs "github.com/opencontainers/runtime-spec/specs-go"`
- Protobuf packages use short aliases: `pb "...proto"`, `metricpb "...proto"`, `epb "...proto"`, `uspb "...proto"`
- Side-effect imports for registration use blank identifier with comment:
  ```go
  _ "gvisor.dev/gvisor/pkg/sentry/platform/platforms" // register all platforms.
  _ "gvisor.dev/gvisor/pkg/sentry/socket/unix"
  ```
- Sub-package abbreviations: `pf "gvisor.dev/gvisor/runsc/boot/portforward"`
- Import rename for conflict with gVisor's own packages (e.g., `context`, `sync`, `time`):
  ```go
  "gvisor.dev/gvisor/pkg/context"     // shadows standard context
  "gvisor.dev/gvisor/pkg/sync"        // shadows standard sync
  sentrytime "gvisor.dev/gvisor/pkg/sentry/time"
  ```

**Path Aliases:**
- Module path: `gvisor.dev/gvisor`
- No Go path aliases (no `replace` directives in `go.mod`)

## Error Handling

**General Go errors (runsc/higher-level code):**
- Use `fmt.Errorf` with `%v` or `%w` for wrapping:
  ```go
  return fmt.Errorf("creating container root directory %q: %v", conf.RootDir, err)
  return fmt.Errorf("cannot render precompiled program for options %v / vars %v: %w", key, vars, err)
  ```
- Fatal errors use `util.Fatalf(format, args...)` which logs + exits with code 128
- Command errors use `util.Errorf(format, args...)` which returns `subcommands.ExitFailure`

**Kernel/sentry errors (pkg/ code):**
- Use `linuxerr` package for Linux errno constants as typed errors:
  ```go
  return linuxerr.EAGAIN
  return linuxerr.EINVAL
  ```
- Use `syserr` package for sandbox-internal errors that translate to errno:
  ```go
  syserr.New("message", errno.ENOENT)
  ```
- Use `errors.Error` (in `pkg/errors`) for typed errno + message pairs

**Cleanup pattern (critical convention):**
- Use `pkg/cleanup.Cleanup` for conditional resource cleanup:
  ```go
  cu := cleanup.Make(func() { resource.Close() })
  defer cu.Clean()
  // ... operations that may fail ...
  cu.Add(func() { resource2.Close() })
  // ... more operations ...
  cu.Release() // on success, prevents cleanup
  return resource, nil
  ```
- Reference: `pkg/cleanup/cleanup.go`, used extensively in `runsc/fsgofer/lisafs.go`, `pkg/lisafs/handlers.go`, `runsc/sandbox/sandbox.go`

## Logging

**Framework:** Custom `pkg/log` package (not standard library or third-party)

**Patterns:**
- Use level-appropriate methods: `log.Debugf()`, `log.Infof()`, `log.Warningf()`
- Guard expensive debug logging with level check:
  ```go
  if log.IsLogging(log.Debug) {
      log.Debugf("expensive format: %v", expensiveComputation())
  }
  ```
- Three log levels: `Warning` (0), `Info` (1), `Debug` (2)
- Emitters implement `log.Emitter` interface; multiple outputs via `log.MultiEmitter`
- For tests, use `log.TestEmitter{t}` wrapping `testing.T`

## Comments

**When to Comment:**
- Every exported type, function, constant, and variable requires a doc comment
- Interface method implementations get `// Method implements Interface.` comment
- Lock ordering documented in package-level comments for complex packages:
  ```go
  // Lock order (outermost locks must be taken first):
  //   Kernel.extMu
  //     TTY.mu
  //       ...
  ```
- Field comments describe purpose, ownership ("owned by the task goroutine"), and synchronization requirements
- Unexported methods that have important preconditions document them:
  ```go
  // Precondition: server's rename mutex must be at least read locked.
  ```

**Annotation Comments (gVisor-specific directives):**
- `// +stateify savable` — marks struct for save/restore serialization (generates `*_state_autogen.go`)
- `// +checklocks` — annotates fields requiring mutex protection
- `// +checklocksignore` — suppresses checklocks analysis on a function
- `// +checkalignedignore` — suppresses alignment checks on a package
- `// +marshal` — generates marshalling code (generates `*_abi_autogen_unsafe.go`)
- `// +marshal boundCheck` — generates marshalling with bounds checking
- `// +marshal slice:SliceName` — generates slice marshalling helpers
- `state:"nosave"` — struct tag indicating field should not be serialized

## Function Design

**Size:** No hard limit, but functions are generally focused. Large kernel structures (e.g., `Kernel`, `Task`) have extensive field lists but methods are reasonably scoped.

**Parameters:**
- `context.Context` (often gVisor's own `pkg/context.Context`) is the first parameter where applicable
- Configuration passed via dedicated struct (e.g., `Args`, `Config`, `Options`)
- Subcommands receive config via `args ...any` and type-assert: `conf := args[0].(*config.Config)`

**Return Values:**
- Standard `(result, error)` pattern
- Multi-return for complex operations: `(string, int, error)` in `createControlSocket`

## Module Design

**Exports:**
- Public API at package level; unexported helpers are internal
- Struct fields use exported names for JSON serialization with `json:"fieldName"` tags
- Configuration fields use `flag:"flag-name"` tags for flag binding

**Barrel Files:**
- Not used. Each package has focused files by concern.

## Struct Tags

- `json:"fieldName"` for serialization in container metadata
- `flag:"flag-name"` for runtime configuration flags
- `state:"nosave"` for fields excluded from save/restore
- `nojson:"true"` for fields excluded from JSON but part of the struct

## Interface Compliance Assertions

Use compile-time interface assertion pattern:
```go
var _ Stack = (*TestStack)(nil)
var _ genericFD = (*ControlFD)(nil)
var _ marshal.Marshallable = (*FDID)(nil)
```

Reference: `pkg/sentry/inet/test_stack.go`, `pkg/lisafs/fd.go`

## Generated Code Patterns

The codebase has extensive code generation (run via Bazel, not `go generate`):

- **State autogen** (`*_state_autogen.go`): Save/restore serialization for `+stateify savable` types
- **ABI autogen** (`*_abi_autogen_unsafe.go`): Marshal/unmarshal for `+marshal` types
- **Mutex wrappers** (`*_mutex.go`): Lock-order-checked mutex types using `pkg/sync/locking`
- **Ref counter** (`*_refs.go`): Reference counting implementations

These files should not be manually edited.

## Concurrency Patterns

**Custom sync package:** `pkg/sync` wraps the standard `sync` package with additional primitives (e.g., `SeqCount` for sequence locks).

**Lock ordering:** Complex packages document lock ordering in package-level comments. Nested locking uses generated mutex types with `NestedLock`/`NestedUnlock`.

**Atomics:** Use `pkg/atomicbitops` for atomic operations on typed wrappers (`Int64`, `Uint64`, `Bool`, `Uint32`), not raw `sync/atomic`.

## Architecture / Build Tags

- Architecture-specific code uses file suffixes (`_amd64.go`, `_arm64.go`) and build tags
- Platform-specific code uses `_linux.go` suffix
- Test-only code uses `//go:build check_invariants` tag (e.g., `pkg/sentry/vfs/debug_testonly.go`)
- Plugin/feature code uses custom build tags: `//go:build network_plugins`
- Test-only config fields prefixed with `TestOnly` and flags prefixed with `TESTONLY-`:
  ```go
  TestOnlyAllowRunAsCurrentUserWithoutChroot bool `flag:"TESTONLY-unsafe-nonroot"`
  ```

## Command Pattern (runsc)

Each runsc subcommand implements `subcommands.Command` interface with:
1. `Name()` — command name
2. `Synopsis()` — brief description
3. `Usage()` — detailed usage string
4. `SetFlags(f *flag.FlagSet)` — flag registration
5. `Execute(ctx, f, args)` — execution logic

Reference: `runsc/cmd/exec.go`, `runsc/cmd/create.go`

## TODO Format

TODOs reference issue trackers with two patterns:
- `TODO(gvisor.dev/issue/NNNN):` for public GitHub issues
- `TODO(b/NNNNNN):` for internal bug tracker references

---

*Convention analysis: 2026-03-08*
