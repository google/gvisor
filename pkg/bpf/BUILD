load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "bpf",
    srcs = [
        "bpf.go",
        "decoder.go",
        "input_bytes.go",
        "interpreter.go",
        "program_builder.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/bpf",
    visibility = ["//visibility:public"],
    deps = ["//pkg/abi/linux"],
)

go_test(
    name = "bpf_test",
    size = "small",
    srcs = [
        "decoder_test.go",
        "interpreter_test.go",
        "program_builder_test.go",
    ],
    embed = [":bpf"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
    ],
)
