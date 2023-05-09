# The gVisor Virtual Filesystem

## Implementation Notes

### Reference Counting

Filesystem, Dentry, Mount, MountNamespace, and FileDescription are all
reference-counted. Mount and MountNamespace are exclusively VFS-managed; when
their reference count reaches zero, VFS releases their resources. Filesystem and
FileDescription management is shared between VFS and filesystem implementations;
when their reference count reaches zero, VFS notifies the implementation by
calling `FilesystemImpl.Release()` or `FileDescriptionImpl.Release()`
respectively and then releases VFS-owned resources. Dentries are exclusively
managed by filesystem implementations; reference count changes are abstracted
through DentryImpl, which should release resources when reference count reaches
zero.

Filesystem references are held by:

-   Mount: Each referenced Mount holds a reference on the mounted Filesystem.

Dentry references are held by:

-   FileDescription: Each referenced FileDescription holds a reference on the
    Dentry through which it was opened, via `FileDescription.vd.dentry`.

-   Mount: Each referenced Mount holds a reference on its mount point and on the
    mounted filesystem root. The mount point is mutable (`mount(MS_MOVE)`).

Mount references are held by:

-   FileDescription: Each referenced FileDescription holds a reference on the
    Mount on which it was opened, via `FileDescription.vd.mount`.

-   Mount: Each referenced Mount holds a reference on its parent, which is the
    mount containing its mount point.

-   VirtualFilesystem: A reference is held on each Mount that has been connected
    to a mount point, but not yet umounted.

MountNamespace and FileDescription references are held by users of VFS. The
expectation is that each `kernel.Task` holds a reference on its corresponding
MountNamespace, and each file descriptor holds a reference on its represented
FileDescription.

Notes:

-   Dentries do not hold a reference on their owning Filesystem. Instead, all
    uses of a Dentry occur in the context of a Mount, which holds a reference on
    the relevant Filesystem (see e.g. the VirtualDentry type). As a corollary,
    when releasing references on both a Dentry and its corresponding Mount, the
    Dentry's reference must be released first (because releasing the Mount's
    reference may release the last reference on the Filesystem, whose state may
    be required to release the Dentry reference).

### The Inheritance Pattern

Filesystem, Dentry, and FileDescription are all concepts featuring both state
that must be shared between VFS and filesystem implementations, and operations
that are implementation-defined. To facilitate this, each of these three
concepts follows the same pattern, shown below for Dentry:

```go
// Dentry represents a node in a filesystem tree.
type Dentry struct {
  // VFS-required dentry state.
  parent *Dentry
  // ...

  // impl is the DentryImpl associated with this Dentry. impl is immutable.
  // This should be the last field in Dentry.
  impl DentryImpl
}

// Init must be called before first use of d.
func (d *Dentry) Init(impl DentryImpl) {
  d.impl = impl
}

// Impl returns the DentryImpl associated with d.
func (d *Dentry) Impl() DentryImpl {
  return d.impl
}

// DentryImpl contains implementation-specific details of a Dentry.
// Implementations of DentryImpl should contain their associated Dentry by
// value as their first field.
type DentryImpl interface {
  // VFS-required implementation-defined dentry operations.
  IncRef()
  // ...
}
```

This construction, which is essentially a type-safe analogue to Linux's
`container_of` pattern, has the following properties:

-   VFS works almost exclusively with pointers to Dentry rather than DentryImpl
    interface objects, such as in the type of `Dentry.parent`. This avoids
    interface method calls (which are somewhat expensive to perform, and defeat
    inlining and escape analysis), reduces the size of VFS types (since an
    interface object is two pointers in size), and allows pointers to be loaded
    and stored atomically using `sync/atomic`. Implementation-defined behavior
    is accessed via `Dentry.impl` when required.

-   Filesystem implementations can access the implementation-defined state
    associated with objects of VFS types by type-asserting or type-switching
    (e.g. `Dentry.Impl().(*myDentry)`). Type assertions to a concrete type
    require only an equality comparison of the interface object's type pointer
    to a static constant, and are consequently very fast.

-   Filesystem implementations can access the VFS state associated with objects
    of implementation-defined types directly.

-   VFS and implementation-defined state for a given type occupy the same
    object, minimizing memory allocations and maximizing memory locality. `impl`
    is the last field in `Dentry`, and `Dentry` is the first field in
    `DentryImpl` implementations, for similar reasons: this tends to cause
    fetching of the `Dentry.impl` interface object to also fetch `DentryImpl`
    fields, either because they are in the same cache line or via next-line
    prefetching.
