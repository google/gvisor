load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "ptrace",
    srcs = [
        "ptrace.go",
        "ptrace_unsafe.go",
        "stub_amd64.s",
        "stub_unsafe.go",
        "subprocess.go",
        "subprocess_amd64.go",
        "subprocess_linux.go",
        "subprocess_linux_amd64_unsafe.go",
        "subprocess_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/platform/ptrace",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/procid",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/interrupt",
        "//pkg/sentry/platform/safecopy",
        "//pkg/sentry/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
