load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "seccomp",
    srcs = [
        "seccomp.go",
        "seccomp_amd64.go",
        "seccomp_arm64.go",
        "seccomp_fuzz_helpers.go",
        "seccomp_optimizer.go",
        "seccomp_rules.go",
        "seccomp_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/log",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "seccomp_test",
    size = "small",
    srcs = [
        "seccomp_test.go",
    ],
    embedsrcs = [
        "//pkg/seccomp/victim",  # keep
    ],
    library = ":seccomp",
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
