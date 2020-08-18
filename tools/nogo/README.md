# Extended "nogo" analysis

This package provides a build aspect that perform nogo analysis. This will be
automatically injected to all relevant libraries when using the default
`go_binary` and `go_library` rules.

It exists for several reasons.

*   The default `nogo` provided by bazel is insufficient with respect to the
    possibility of binary analysis. This package allows us to analyze the
    generated binary in addition to using the standard analyzers.

*   The configuration provided in this package is much richer than the standard
    `nogo` JSON blob. Specifically, it allows us to exclude specific structures
    from the composite rules (such as the Ranges that are common with the set
    types).

*   The bazel version of `nogo` is run directly against the `go_library` and
    `go_binary` targets, meaning that any change to the configuration requires a
    rebuild from scratch (for some reason included all C++ source files in the
    process). Using an aspect is more efficient in this regard.

*   The checks supported by this package are exported as tests, which makes it
    easier to reason about and plumb into the build system.

*   For uninteresting reasons, it is impossible to integrate the default `nogo`
    analyzer provided by bazel with internal Google tooling. To provide a
    consistent experience, this package allows those systems to be unified.

To use this package, import `nogo_test` from `defs.bzl` and add a single
dependency which is a `go_binary` or `go_library` rule.
