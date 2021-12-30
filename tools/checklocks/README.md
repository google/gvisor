# CheckLocks Analyzer

<!--* freshness: { owner: 'gvisor-eng' reviewed: '2021-10-20' } *-->

Checklocks is an analyzer for lock and atomic constraints. The analyzer relies
on explicit annotations to identify fields that should be checked for access.

## Atomic annotations

Individual struct members may be noted as requiring atomic access. These
annotations are of the form:

```go
type foo struct {
  // +checkatomic
  bar int32
}
```

This will ensure that all accesses to bar are atomic, with the exception of
operations on newly allocated objects.

## Lock annotations

Individual struct members may be protected by annotations that indicate locking
requirements for accessing members. These annotations are of the form:

```go
type foo struct {
    mu sync.Mutex
    // +checklocks:mu
    bar int

    foo int  // No annotation on foo means it's not guarded by mu.

    secondMu sync.Mutex

    // Multiple annotations indicate that both must be held but the
    // checker does not assert any lock ordering.
    // +checklocks:secondMu
    // +checklocks:mu
    foobar int
}
```

The checklocks annotation may also apply to functions. For example:

```go
// +checklocks:f.mu
func (f *foo) doThingLocked() { }
```

This will check that the "f.mu" is locked for any calls, where possible.

In case of functions which initialize structs that may have annotations one can
use the following annotation on the function to disable reporting by the lock
checker. The lock checker will still track any mutexes acquired or released but
won't report any failures for this function for unguarded field access.

```go
// +checklocks:ignore
func newXXX() *X {
...
}
```

***The checker treats both 'sync.Mutex' and 'sync.RWMutex' identically, i.e, as
a sync.Mutex. The checker does not distinguish between read locks vs. exclusive
locks and treats all locks as exclusive locks***.

For cases the checker is able to correctly handle today please see test/test.go.

The checklocks check also flags any invalid annotations where the mutex
annotation refers either to something that is not a 'sync.Mutex' or
'sync.RWMutex' or where the field does not exist at all. This will prevent the
annotations from becoming stale over time as fields are renamed, etc.

## Lock suggestions

Based on locks held during field access, the analyzer will suggest annotations.
These can be ignored with the standard `+checklocksignore` annotation.

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

## Currently not supported

1.  Anonymous functions are not correctly evaluated. The analyzer does not
    currently support specifying annotations on anonymous functions as a result
    evaluation of a function that accesses protected fields will fail.

```go
type A struct {
  mu sync.Mutex

  // +checklocks:mu
  x int
}

func abc() {
  var a A
  f := func()  { a.x = 1 }  <=== This line will be flagged by analyzer
  a.mu.Lock()
  f()
  a.mu.Unlock()
}
```

### Explicitly Not Supported

1.  The checker will not support guards on anything other than the cases
    described above. For example, global mutexes cannot be referred to by
    checklocks. Only struct members can be used.

2.  The checker will not support checking for lock ordering violations.

## Mixed mode

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
