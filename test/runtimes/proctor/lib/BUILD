load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "lib",
    srcs = [
        "go.go",
        "java.go",
        "lib.go",
        "nodejs.go",
        "php.go",
        "python.go",
    ],
    visibility = ["//test/runtimes/proctor:__pkg__"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

go_test(
    name = "lib_test",
    size = "small",
    srcs = ["lib_test.go"],
    library = ":lib",
    deps = ["//pkg/test/testutil"],
)
