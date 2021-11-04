load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

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
        "defer.go",
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
)
