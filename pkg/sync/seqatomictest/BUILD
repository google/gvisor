load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_generics:defs.bzl", "go_template_instance")

go_template_instance(
    name = "seqatomic_int",
    out = "seqatomic_int.go",
    package = "seqatomic",
    suffix = "Int",
    template = "//pkg/sync:generic_seqatomic",
    types = {
        "Value": "int",
    },
)

go_library(
    name = "seqatomic",
    srcs = ["seqatomic_int.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sync/seqatomic",
    deps = [
        "//pkg/sync",
    ],
)

go_test(
    name = "seqatomic_test",
    size = "small",
    srcs = ["seqatomic_test.go"],
    embed = [":seqatomic"],
    deps = [
        "//pkg/sync",
    ],
)
