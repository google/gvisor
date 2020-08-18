load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_library(
    name = "pool",
    srcs = [
        "pool.go",
    ],
    deps = [
        "//pkg/sync",
    ],
)

go_test(
    name = "pool_test",
    size = "small",
    srcs = [
        "pool_test.go",
    ],
    library = ":pool",
)
