load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "goid",
    srcs = [
        "goid.go",
        "goid_amd64.tmpl.s",
        "goid_arm64.tmpl.s",
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
