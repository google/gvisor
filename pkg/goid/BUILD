load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "goid",
    srcs = [
        "goid.go",
        "goid_amd64.s",
        "goid_arm64.s",
    ],
    stateify = False,
    visibility = ["//visibility:public"],
)

go_test(
    name = "goid_test",
    size = "small",
    srcs = [
        "goid_test.go",
    ],
    library = ":goid",
)
