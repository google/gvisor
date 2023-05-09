# CheckLocks Analyzer

<!--* freshness: { owner: 'gvisor-eng' reviewed: '2022-02-02' } *-->

Checklocks is an analyzer for lock and atomic constraints. The analyzer relies
on explicit annotations to identify fields that should be checked for access.

## Installation and Usage

The analyzer is integrated into the gVisor `nogo` framework. It automatically
applies to all code in this repository.

For external usage and to iterate quickly, it may be used as part of `go vet`.
You can install the tool separately via:

```sh
go install gvisor.dev/gvisor/tools/checklocks/cmd/checklocks@go
```

And, if installed to the default path, run it via:

```sh
go vet -vettool=$HOME/go/bin/checklocks ./...
```

## Annotations

This analyzer supports annotations for atomic access and lock enforcement, in
order to allow for mixed semantics. These are first described separately, then
the combination is discussed.

### Atomic Access Enforcement

Individual struct members may be noted as requiring atomic access. These
annotations are of the form `+checkatomic`, for example:

```go
type foo struct {
  // +checkatomic
  bar int32
}
```

This will ensure that all accesses to bar are atomic, with the exception of
operations on newly allocated objects (when detectable).

## Lock Enforcement

Individual struct members may be protected by annotations that indicate locking
requirements for accessing members. These annotations are of the form
`+checklocks`, for example:

```go
type foo struct {
    mu sync.Mutex

    // +checklocks:mu
    bar int

    foo int  // No annotation on foo means it's not guarded by mu.

    secondMu sync.RWMutex

    // Multiple annotations indicate that both must be held but the
    // checker does not assert any lock ordering.
    // +checklocks:secondMu
    // +checklocks:mu
    foobar int
}
```

These semantics are enforcable on `sync.Mutex`, `sync.RWMutex` and `sync.Locker`
fields. Semantics with respect to reading and writing are automatically detected
and enforced. If an access is read-only, then the lock need only be held as a
read lock, in the case of an `sync.RWMutex`.

The locks must be resolvable within the scope of the declaration. This means the
lock must refer to one of:

*   A struct-local lock (e.g. mu).
*   A lock resolvable from the local struct (e.g. fieldX.mu).
*   A global lock (e.g. globalMu).
*   A lock resolvable from a global struct (e.g. globalX.mu).

Like atomic access enforcement, checks may be elided on newly allocated objects.

### Function Annotations

The `+checklocks` annotation may apply to functions. For example:

```go
// +checklocks:f.mu
func (f *foo) doThingLocked() { }
```

The field provided in the `+checklocks` annotation must be resolvable as one of:

*   A parameter, receiver or return value (e.g. mu).
*   A lock resolvable from a parameter, receiver or return value (e.g. f.mu).
*   A global lock (e.g. globalMu).
*   A lock resolvable from a global struct (e.g. globalX.mu).

This annotation will ensure that the given lock is held for all calls, and all
analysis of this function will assume that this is the case.

Additional variants of the `+checklocks` annotation are supported for functions:

*   `+checklocksread`: This enforces that at least a read lock is held. Note
    that this assumption will apply locally, so accesses and function calls will
    assume that only a read lock is available.
*   `+checklocksacquire`: This enforces that the given lock is *not* held on
    entry, but it will be held on exit. This assertion will be checked locally
    and applied to the caller's lock state.
*   `+checklocksrelease`: This enforces that the given lock is held on entry,
    and will be release on exit. This assertion is checked locally and applied
    to the caller's lock state.
*   `+checklocksacquireread`: A read variant of `+checklocksacquire`.
*   `+checklocksreleaseread`: A read variant of `+checklocksrelease`.
*   `+checklocksalias:a.b.c=x.y`: For parameters with complex relationships,
    this annotation can be used to specify that the `a.b.c` lock is equivalent
    to the `x.y` state. That is, any operation on either of these locks applies
    to both, and any assertions that can be made about either applies to both.

For examples of these cases see the tests.

#### Anonymous Functions and Closures

Anonymous functions and closures cannot be annotated.

If anonymous functions and closures are bound and invoked within a single scope,
the analysis will happen with the available lock state. For example, the
following will not report any violations:

```go
func foo(ts *testStruct) {
  x := func() {
    ts.guardedField = 1
  }
  ts.mu.Lock()
  x() // We know the context x is being invoked.
  ts.mu.Unlock()
}
```

This pattern often applies to defer usage, which allows defered functions to be
fully analyzed with the lock state at time of execution.

However, if a closure is passed to another function, the anonymous function
backing that closure will be analyzed assuming no available lock state. For
example, the following will report violations:

```go
func runFunc(f func()) {
  f()
}

func foo(ts *testStruct) {
  x := func() {
    ts.guardedField = 1
  }
  ts.mu.Lock()
  runFunc(x) // We can't know what will happen with x.
  ts.mu.Unlock()
}
```

Since x cannot be annotated, this may require use of the force annotation used
below. However, if anonymous functions and closures require annotations, there
may be an opportunity to split them into named functions for improved analysis
and debuggability, and avoid the need to use force annotations.

### Mixed Atomic Access and Lock Enforcement

Some members may allow read-only atomic access, but be protected against writes
by a mutex. Generally, this imposes the following requirements:

For a read, one of the following must be true:

1.  A lock held be held.
1.  The access is atomic.

For a write, both of the following must be true:

1.  The lock must be held.
1.  The write must be atomic.

In order to annotate a relevant field, simply apply *both* annotations from
above. For example:

```go
type foo struct {
  mu sync.Mutex
  // +checklocks:mu
  // +checkatomic
  bar int32
}
```

This enforces that the preconditions above are upheld.

## Ignoring and Forcing

From time to time, it may be necessary to ignore results produced by the
analyzer. These can be disabled on a per-field, per-function or per-line basis.

For fields, only lock suggestions may be ignored. See below for details.

For functions, the `+checklocksignore` annotation can be applied. This prevents
any local analysis from taking place. Note that the other annotations can still
be applied to the function, which will enforce assertions in caller analysis.
For example:

```go
// +checklocks:ts.mu
// +checklocksignore
func foo(ts *testStruct) {
  ts.guardedField = 1
}
```

For individual lines, the `+checklocksforce` annotation can be applied after the
statement. This does not simply ignore the line, rather it *forces* the
necessary assertion to become true. For example, if a lock must be held, this
annotation will mark that lock as held for all subsequent lines. For example:

```go
func foo(ts *testStruct) {
  ts.guardedField = 1 // +checklocksforce: don't care about locking.
}
```

In general, both annotations should be highly discouraged. It should be possible
to avoid their use by factoring functions in such a way that annotations can be
applied consistently and without the need for ignoring and forcing.

## Testing

Tests can be built using the `+checklocksfail` annotation. When applied after a
statement, these will generate a report if the line does *not* fail an
assertion. For example:

```go
func foo(ts *testStruct) {
  ts.guardedField = 1 // +checklocksfail: violation.
}
```

These annotations are primarily useful for analyzer development and testing.

## Suggestions

Based on locks held during field access, the analyzer may suggest annotations.
These can be ignored with the `+checklocksignore` annotation on fields.

```go
type foo struct {
  mu sync.Mutex
  // +checklocksignore: mu is not required, it just happens to be held always.
  bar int32
}
```

The annotation will be generated when the lock is held the vast majority of the
time the field is accessed. Note that it is possible for this frequency to be
greater than 100%, if the lock is held multiple times. For example:

```go
func foo(ts1 *testStruct, ts2 *testStruct) {
  ts1.Lock()
  ts2.Lock()
  ts1.guardedField = 1 // 200% locks held.
  ts1.Unlock()
  ts2.Unlock()
}
```

It should be expected that this annotation is also rare. If the field is not
protected by the mutex, it suggests that the critical section could be made
smaller by restructuring the code or the structure instead of applying the
ignore annotation.
