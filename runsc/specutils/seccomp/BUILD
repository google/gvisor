load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "seccomp",
    srcs = [
        "audit_amd64.go",
        "audit_arm64.go",
        "seccomp.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/log",
        "//pkg/seccomp",
        "//pkg/sentry/kernel",
        "//pkg/sentry/syscalls/linux",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "seccomp_test",
    size = "small",
    srcs = ["seccomp_test.go"],
    library = ":seccomp",
    deps = [
        "//pkg/binary",
        "//pkg/bpf",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
