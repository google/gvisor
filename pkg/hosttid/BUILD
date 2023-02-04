load("//tools:defs.bzl", "arch_genrule", "go_library", "go_test", "select_arch")
load("//tools/nogo:defs.bzl", "nogo_facts")

package(licenses = ["notice"])

nogo_facts(
    name = "hosttid_impl",
    srcs = ["hosttid.go"],
    output = "hosttid_impl.s",
    template = select_arch(
        amd64 = "hosttid_amd64.s",
        arm64 = "hosttid_arm64.s",
    ),
)

arch_genrule(
    name = "hosttid_impl_arch",
    src = ":hosttid_impl",
    template = "hosttid_impl_%s.s",
)

go_library(
    name = "hosttid",
    srcs = [
        "hosttid.go",
        ":hosttid_impl_arch",
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
