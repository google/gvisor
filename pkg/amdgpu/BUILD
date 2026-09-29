load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "amdgpu",
    srcs = ["sysfs.go"],
    visibility = ["//visibility:public"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

go_test(
    name = "amdgpu_test",
    srcs = ["sysfs_test.go"],
    library = ":amdgpu",
)
