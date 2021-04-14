load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "gohacks",
    srcs = [
        "gohacks_unsafe.go",
    ],
    stateify = False,
    visibility = ["//:sandbox"],
)

go_test(
    name = "gohacks_test",
    size = "small",
    srcs = ["gohacks_test.go"],
    library = ":gohacks",
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
