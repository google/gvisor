# CheckLocks Analyzer

<!--* freshness: { owner: 'gvisor-eng' reviewed: '2020-10-05' } *-->

Checklocks is a nogo analyzer that at compile time uses Go's static analysis
tools to identify and flag cases where a field that is guarded by a mutex in the
same struct is accessed outside of a mutex lock.

The analyzer relies on explicit '// +checklocks:<mutex-name>' kind of
annotations to identify fields that should be checked for access.

Individual struct members may be protected by annotations that indicate how they
must be accessed. These annotations are of the form:

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

# Currently not supported

1.  The analyzer does not correctly handle deferred functions. e.g The following
    code is not correctly checked by the analyzer. The defer call is never
    evaluated. As a result if the lock was to be say unlocked twice via deferred
    functions it would not be caught by the analyzer.

    Similarly deferred anonymous functions are not evaluated either.

```go
type A struct {
  mu sync.Mutex

  // +checklocks:mu
  x int
}

func abc() {
  var a A
  a.mu.Lock()
  defer a.mu.Unlock()
  defer a.mu.Unlock()
  a.x = 1
}
```

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

# Explicitly Not Supported

1.  Checking for embedded mutexes as sync.Locker rather than directly as
    'sync.Mutex'. In other words, the checker will not track mutex Lock and
    Unlock() methods where the mutex is behind an interface dispatch.

An example that we won't handle is shown below (this in fact will fail to
build):

```go
type A struct {
  mu sync.Locker

  // +checklocks:mu
  x int
}

func abc() {
   mu sync.Mutex
   a := A{mu: &mu}
   a.x = 1 // This won't be flagged by copylocks checker.
}

```

1.  The checker will not support guards on anything other than the cases
    described above. For example, global mutexes cannot be referred to by
    checklocks. Only struct members can be used.

2.  The checker will not support checking for lock ordering violations.
