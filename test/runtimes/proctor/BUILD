load("//tools:defs.bzl", "go_binary", "go_test")

package(licenses = ["notice"])

go_binary(
    name = "proctor",
    srcs = [
        "go.go",
        "java.go",
        "nodejs.go",
        "php.go",
        "proctor.go",
        "python.go",
    ],
    pure = True,
    visibility = ["//test/runtimes:__pkg__"],
)

go_test(
    name = "proctor_test",
    size = "small",
    srcs = ["proctor_test.go"],
    library = ":proctor",
    nogo = False,  # FIXME(gvisor.dev/issue/3374): Not working with all build systems.
    pure = True,
    deps = [
        "//pkg/test/testutil",
    ],
)
