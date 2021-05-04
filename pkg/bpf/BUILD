load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "bpf",
    srcs = [
        "bpf.go",
        "decoder.go",
        "input_bytes.go",
        "interpreter.go",
        "program_builder.go",
    ],
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
    library = ":bpf",
    deps = [
        "//pkg/abi/linux",
        "//pkg/hostarch",
        "//pkg/marshal",
    ],
)
