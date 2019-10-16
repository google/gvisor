load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "seqatomic_int",
    out = "seqatomic_int_unsafe.go",
    package = "seqatomic",
    suffix = "Int",
    template = "//third_party/gvsync:generic_seqatomic",
    types = {
        "Value": "int",
    },
)

go_library(
    name = "seqatomic",
    srcs = ["seqatomic_int_unsafe.go"],
    importpath = "gvisor.dev/gvisor/third_party/gvsync/seqatomic",
    deps = [
        "//third_party/gvsync",
    ],
)

go_test(
    name = "seqatomic_test",
    size = "small",
    srcs = ["seqatomic_test.go"],
    embed = [":seqatomic"],
    deps = [
        "//third_party/gvsync",
    ],
)
