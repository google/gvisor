load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "goid",
    srcs = [
        "goid.go",
        "goid_amd64.s",
        "goid_arm64.s",
        "goid_race.go",
        "goid_unsafe.go",
    ],
    visibility = ["//visibility:public"],
)

go_test(
    name = "goid_test",
    size = "small",
    srcs = [
        "empty_test.go",
        "goid_test.go",
    ],
    library = ":goid",
)
