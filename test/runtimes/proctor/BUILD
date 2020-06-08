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
    pure = True,
    deps = [
        "//pkg/test/testutil",
    ],
)
