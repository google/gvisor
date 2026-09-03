load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "rdma",
    srcs = [
        "collect.go",
        "snapshot.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "rdma_test",
    srcs = ["snapshot_test.go"],
    library = ":rdma",
)
