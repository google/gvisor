load("//tools:arch.bzl", "arch_genrule", "select_arch")
load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/nogo:defs.bzl", "nogo_facts")

package(licenses = ["notice"])

nogo_facts(
    name = "goid_impl",
    srcs = ["goid.go"],
    output = "goid_impl.s",
    template = select_arch(
        amd64 = "goid_amd64.s",
        arm64 = "goid_arm64.s",
    ),
)

arch_genrule(
    name = "goid_impl_arch",
    src = ":goid_impl",
    template = "goid_impl_%s.s",
)

go_library(
    name = "goid",
    srcs = [
        "goid.go",
        ":goid_impl_arch",
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
