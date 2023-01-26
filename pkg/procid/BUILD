load("//tools:defs.bzl", "arch_genrule", "go_library", "go_test", "select_arch")
load("//tools/nogo:defs.bzl", "nogo_facts")

package(licenses = ["notice"])

nogo_facts(
    name = "procid_impl",
    srcs = ["procid.go"],
    output = "procid_impl.s",
    template = select_arch(
        amd64 = "procid_amd64.s",
        arm64 = "procid_arm64.s",
    ),
)

arch_genrule(
    name = "procid_impl_arch",
    src = ":procid_impl",
    template = "procid_impl_%s.s",
)

go_library(
    name = "procid",
    srcs = [
        "procid.go",
        ":procid_impl_arch",
    ],
    visibility = ["//visibility:public"],
)

go_test(
    name = "procid_test",
    size = "small",
    srcs = [
        "procid_test.go",
    ],
    library = ":procid",
    deps = [
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "procid_net_test",
    size = "small",
    srcs = [
        "procid_net_test.go",
        "procid_test.go",
    ],
    library = ":procid",
    deps = [
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
