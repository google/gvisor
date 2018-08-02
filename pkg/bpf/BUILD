package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify", "go_test")

go_stateify(
    name = "bpf_state",
    srcs = [
        "interpreter.go",
    ],
    out = "bpf_state.go",
    package = "bpf",
)

go_library(
    name = "bpf",
    srcs = [
        "bpf.go",
        "bpf_state.go",
        "decoder.go",
        "input_bytes.go",
        "interpreter.go",
        "program_builder.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/bpf",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/state",
    ],
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
