load("@bazel_skylib//rules:run_binary.bzl", "run_binary")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "secfuzz",
    testonly = 1,
    srcs = [
        "secfuzz.go",
        "secfuzz_covermeup.go",
        "secfuzz_nocoverageguidance.go",
    ],
    importpath = "gvisor.dev/gvisor/test/secfuzz",
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/sentry",
        "//pkg/atomicbitops",
        "//pkg/bpf",
        "//pkg/seccomp",
        "//pkg/sync",
    ],
)

go_test(
    name = "secfuzz_test",
    size = "small",
    srcs = ["coverage_test.go"],
    embed = [":secfuzz"],
    deps = ["//pkg/bpf"],
)

run_binary(
    name = "secfuzz_covermeup",
    srcs = ["secfuzz_covermeup.tmpl"],
    outs = ["secfuzz_covermeup.go"],
    args = [
        "$(location secfuzz_covermeup.tmpl)",
        "$(location secfuzz_covermeup.go)",
    ],
    tool = "//test/secfuzz/coveragegen",
)
