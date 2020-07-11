load("//tools:defs.bzl", "go_binary", "go_test")

package(licenses = ["notice"])

go_binary(
    name = "runner",
    testonly = 1,
    srcs = ["main.go"],
    visibility = ["//test/runtimes:__pkg__"],
    deps = [
        "//pkg/log",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)

go_test(
    name = "exclude_test",
    size = "small",
    srcs = ["exclude_test.go"],
    library = ":runner",
)
