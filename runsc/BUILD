package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "runsc",
    srcs = [
        "main.go",
    ],
    pure = "on",
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"main.gitRevision": "{GIT_REVISION}"},
    deps = [
        "//pkg/log",
        "//runsc/boot",
        "//runsc/cmd",
        "@com_github_google_subcommands//:go_default_library",
    ],
)

# The runsc-race target is a race-compatible BUILD target. This must be built
# via "bazel build --features=race //runsc:runsc-race", since the race feature
# must apply to all dependencies due a bug in gazelle file selection.  The pure
# attribute must be off because the race detector requires linking with non-Go
# components, although we still require a static binary.
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
    static = "on",
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"main.gitRevision": "{GIT_REVISION}"},
    deps = [
        "//pkg/log",
        "//runsc/boot",
        "//runsc/cmd",
        "//runsc/specutils",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
