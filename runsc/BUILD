load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "runsc",
    srcs = [
        "main.go",
    ],
    pure = True,
    tags = ["staging"],
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//runsc/cli",
        "//runsc/version",
    ],
)

# The runsc-race target is a race-compatible BUILD target. This must be built
# via: bazel build --features=race :runsc-race
#
# This is neccessary because the race feature must apply to all dependencies
# due a bug in gazelle file selection.  The pure attribute must be off because
# the race detector requires linking with non-Go components, although we still
# require a static binary.
#
# Note that in the future this might be convertible to a compatible target by
# using the pure and static attributes within a select function, but select is
# not currently compatible with string attributes [1].
#
# [1] https://github.com/bazelbuild/bazel/issues/1698
go_binary(
    name = "runsc-race",
    srcs = [
        "main.go",
    ],
    gotags = ["lockdep"],
    static = True,
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//runsc/cli",
        "//runsc/version",
    ],
)

sh_test(
    name = "version_test",
    size = "small",
    srcs = ["version_test.sh"],
    args = ["$(location :runsc)"],
    data = [":runsc"],
)
