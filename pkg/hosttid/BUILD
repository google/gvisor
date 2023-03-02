load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "hosttid",
    srcs = [
        "hosttid.go",
        "hosttid_amd64.s",
        "hosttid_arm64.s",
    ],
    visibility = ["//visibility:public"],
)

go_test(
    name = "hosttid_test",
    size = "small",
    srcs = [
        "hosttid_test.go",
    ],
    library = ":hosttid",
    deps = [
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "hosttid_net_test",
    size = "small",
    srcs = [
        "hosttid_net_test.go",
        "hosttid_test.go",
    ],
    library = ":hosttid",
    deps = [
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
