This package implements the go_marshal utility.

# Overview

`go_marshal` is a code generation utility similar to `go_stateify` for
marshalling go data structures to and from memory.

`go_marshal` attempts to improve on `binary.Write` and the sentry's
`binary.Marshal` by moving the expensive use of reflection from runtime to
compile-time.

`go_marshal` automatically generates implementations for `marshal.Marshallable`
interface. Data structures that require custom serialization can be accomodated
through a manual implementation this interface.

Data structures can be flagged for code generation by adding a struct-level
comment `// +marshal`. For additional details and options, see the documentation
for the `marshal.Marshallable` interface.

# Usage

See `defs.bzl`: a new rule is provided, `go_marshal`.

Under the hood, the `go_marshal` rule is used to generate a file that will
appear in a Go target; the output file should appear explicitly in a srcs list.
For example (note that the above is the preferred method):

```
load("<PKGPATH>/gvisor/tools/go_marshal:defs.bzl", "go_marshal")

go_marshal(
    name = "foo_abi",
    srcs = ["foo.go"],
    out = "foo_abi.go",
    package = "foo",
)

go_library(
    name = "foo",
    srcs = [
        "foo.go",
        "foo_abi.go",
    ],
    ...
)
```

As part of the interface generation, `go_marshal` also generates some tests for
sanity checking the struct definitions for potential alignment issues, and a
simple round-trip test through Marshal/Unmarshal to verify the implementation.
These tests use reflection to verify properties of the ABI struct, and should be
considered part of the generated interfaces (but are too expensive to execute at
runtime). Ensure these tests run at some point.

# Restrictions

Not all valid go type definitions can be used with `go_marshal`. `go_marshal` is
intended for ABI structs, which have these additional restrictions:

-   At the moment, `go_marshal` only supports struct declarations.

-   Structs are marshalled as packed types. This means no implicit padding is
    inserted between fields shorter than the platform register size. For
    alignment, manually insert padding fields.

-   Structs used with `go_marshal` must have a compile-time static size. This
    means no dynamically sizes fields like slices or strings. Use statically
    sized array (byte arrays for strings) instead.

-   No pointers, channel, map or function pointer fields, and no fields that are
    arrays of these types. These don't make sense in an ABI data structure.

-   We could support opaque pointers as `uintptr`, but this is currently not
    implemented. Implementing this would require handling the architecture
    dependent native pointer size.

-   Fields must either be a primitive integer type (`byte`,
    `[u]int{8,16,32,64}`), or of a type that implements `marshal.Marshallable`.

-   `int` and `uint` fields are not allowed. Use an explicitly-sized numeric
    type.

-   `float*` fields are currently not supported, but could be if necessary.

# Appendix

## Working with Non-Packed Structs

ABI structs must generally be packed types, meaning they should have no implicit
padding between short fields. However, if a field is tagged
`marshal:"unaligned"`, `go_marshal` will fall back to a safer but slower
mechanism to deal with potentially unaligned fields.

Note that the non-packed property is inheritted by any other struct that embeds
this struct, since the `go_marshal` tool currently can't reason about alignments
for embedded structs that are not aligned.

Because of this, it's generally best to avoid using `marshal:"unaligned"` and
insert explicit padding fields instead.

## Modifying the `go_marshal` Tool

The following are some guidelines for modifying the `go_marshal` tool:

-   The `go_marshal` tool currently does a single pass over all types requesting
    code generation, in arbitrary order. This means the generated code can't
    directly obtain information about embedded marshallable types at
    compile-time. One way to work around this restriction is to add a new
    Marshallable interface method providing this piece of information, and
    calling it from the generated code. Use this sparingly, as we want to rely
    on compile-time information as much as possible for performance.

-   No runtime reflection in the code generated for the marshallable interface.
    The entire point of the tool is to avoid runtime reflection. The generated
    tests may use reflection.
