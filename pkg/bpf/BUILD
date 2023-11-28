load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "bpf",
    srcs = [
        "bpf.go",
        "bpf_unsafe.go",
        "decoder.go",
        "input_bytes.go",
        "interpreter.go",
        "optimizer.go",
        "program_builder.go",
    ],
    imports = ["gvisor.dev/gvisor/pkg/abi/linux"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/abi/linux"],
)

go_test(
    name = "bpf_test",
    size = "small",
    srcs = [
        "bpf_test.go",
        "decoder_test.go",
        "interpreter_test.go",
        "optimizer_test.go",
        "program_builder_test.go",
    ],
    library = ":bpf",
    deps = [
        "//pkg/abi/linux",
        "//pkg/hostarch",
        "//pkg/marshal",
    ],
)
