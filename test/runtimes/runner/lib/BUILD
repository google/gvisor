load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "lib",
    testonly = 1,
    srcs = [
        "go_test_dependency_go118.go",
        "go_test_dependency_not_go118.go",
        "lib.go",
    ],
    visibility = ["//test/runtimes/runner:__pkg__"],
    deps = [
        "//pkg/log",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)

go_test(
    name = "lib_test",
    size = "small",
    srcs = ["exclude_test.go"],
    library = ":lib",
)
