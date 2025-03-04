load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "goid",
    srcs = [
        "goid.go",
        "goid_122_amd64.s",
        "goid_122_arm64.s",
        "goid_123_amd64.s",
        "goid_123_arm64.s",
        "goid_125_amd64.s",
        "goid_125_arm64.s",
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
