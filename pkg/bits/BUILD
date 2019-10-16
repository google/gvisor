load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

package(licenses = ["notice"])

go_library(
    name = "bits",
    srcs = [
        "bits.go",
        "bits32.go",
        "bits64.go",
        "uint64_arch.go",
        "uint64_arch_amd64_asm.s",
        "uint64_arch_arm64_asm.s",
        "uint64_arch_generic.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/bits",
    visibility = ["//:sandbox"],
)

go_template(
    name = "bits_template",
    srcs = ["bits_template.go"],
    types = [
        "T",
    ],
)

go_template_instance(
    name = "bits64",
    out = "bits64.go",
    package = "bits",
    suffix = "64",
    template = ":bits_template",
    types = {
        "T": "uint64",
    },
)

go_template_instance(
    name = "bits32",
    out = "bits32.go",
    package = "bits",
    suffix = "32",
    template = ":bits_template",
    types = {
        "T": "uint32",
    },
)

go_test(
    name = "bits_test",
    size = "small",
    srcs = ["uint64_test.go"],
    embed = [":bits"],
)
