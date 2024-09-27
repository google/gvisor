load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "rawsyscall",
    srcs = [
        "rawsyscall.go",
        "rawsyscall_amd64.s",
        "rawsyscall_arm64.s",
    ],
    visibility = ["//:sandbox"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
