load("//tools:defs.bzl", "go_binary", "go_test")

package(licenses = ["notice"])

go_binary(
    name = "runner",
    testonly = 1,
    srcs = ["main.go"],
    visibility = ["//test/runtimes:__pkg__"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)

go_test(
    name = "blacklist_test",
    size = "small",
    srcs = ["blacklist_test.go"],
    library = ":runner",
)
