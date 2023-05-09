load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "memutil",
    srcs = [
        "memfd_linux_unsafe.go",
        "memutil_unsafe.go",
        "mmap.go",
    ],
    visibility = ["//visibility:public"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
