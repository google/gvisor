load("//tools:defs.bzl", "go_library")

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
    # Disable generated marshal/state sources so they do not add unexpected
    # diagnostics to this fixture.
    marshal = False,
    stateify = False,
    deps = [
        "//pkg/atomicbitops",
        "//tools/checklocks/test/crosspkg",
    ],
)
