# Reference Counting

Go does not offer a reliable way to couple custom resource management with
object lifetime. As a result, we need to manually implement reference counting
for many objects in gVisor to make sure that resources are acquired and released
appropriately. For example, the filesystem has many reference-counted objects
(file descriptions, dentries, inodes, etc.), and it is important that each
object persists while anything holds a reference on it and is destroyed once all
references are dropped.

We provide a template in `refs_template.go` that can be applied to most objects
in need of reference counting. It contains a simple `Refs` struct that can be
incremented and decremented, and once the reference count reaches zero, a
destructor can be called. Note that there are some objects (e.g. `gofer.dentry`,
`overlay.dentry`) that should not immediately be destroyed upon reaching zero
references; in these cases, this template cannot be applied.

# Reference Checking

Unfortunately, manually keeping track of reference counts is extremely error
prone, and improper accounting can lead to production bugs that are very
difficult to root cause.

We have several ways of discovering reference count errors in gVisor. Any
attempt to increment/decrement a `Refs` struct with a count of zero will trigger
a sentry panic, since the object should have been destroyed and become
unreachable. This allows us to identify missing increments or extra decrements,
which cause the reference count to be lower than it should be: the count will
reach zero earlier than expected, and the next increment/decrement--which should
be valid--will result in a panic.

It is trickier to identify extra increments and missing decrements, which cause
the reference count to be higher than expected (i.e. a “reference leak”).
Reference leaks prevent resources from being released properly and can translate
to various issues that are tricky to diagnose, such as memory leaks. The
following section discusses how we implement leak checking.

## Leak Checking

When leak checking is enabled, reference-counted objects are added to a global
map when constructed and removed when destroyed. Near the very end of sandbox
execution, once no reference-counted objects should still be reachable, we
report everything left in the map as having leaked. Leak-checking objects
implement the `CheckedObject` interface, which allows us to print informative
warnings for each of the leaked objects.

Leak checking is provided by `refs_template`, but objects that do not use the
template will also need to implement `CheckedObject` and be manually
registered/unregistered from the map in order to be checked.

Note that leak checking affects performance and memory usage, so it should only
be enabled in testing environments.

## Debugging

Even with the checks described above, it can be difficult to track down the
exact source of a reference counting error. The error may occur far before it is
discovered (for instance, a missing `IncRef` may not be discovered until a
future `DecRef` makes the count negative). To aid in debugging, `refs_template`
provides the `enableLogging` option to log every `IncRef`, `DecRef`, and leak
check registration/unregistration, along with the object address and a call
stack. This allows us to search a log for all of the changes to a particular
object's reference count, which makes it much easier to identify the absent or
extraneous operation(s). The reference-counted objects that do not use
`refs_template` also provide logging, and others defined in the future should do
so as well.
