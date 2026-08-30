load("//tools:defs.bzl", "go_library")
load("//tools/nogo:defs.bzl", "nogo_config", "nogo_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "test",
    srcs = [
        "aliases.go",
        "alignment.go",
        "anon.go",
        "atomics.go",
        "basics.go",
        "branches.go",
        "closures.go",
        "cyclic.go",
        "defer.go",
        "generics.go",
        "globals.go",
        "incompat.go",
        "inferred.go",
        "locker.go",
        "methods.go",
        "parameters.go",
        "return.go",
        "rwmutex.go",
        "test.go",
    ],
    # This ensures that there are no dependencies, since we want to explicitly
    # control expected failures for analysis.
    marshal = False,
    stateify = False,
    deps = ["//tools/checklocks/test/crosspkg"],
)

nogo_config(
    name = "strict_config",
    srcs = ["strict.yaml"],
)

# Production filters suppress inference hints and incompatible return states.
# Check these fixtures without those filters so diagnostic regressions fail CI.
nogo_test(
    name = "strict_nogo",
    srcs = [
        "aliases.go",
        "inferred.go",
    ],
    config = ":strict_config",
    tags = ["nogo"],
    deps = [":test"],
)
