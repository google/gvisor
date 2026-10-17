load("//pkg/seccomp/precompiledseccomp:defs.bzl", "precompiled_seccomp_rules")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

precompiled_seccomp_rules(
    name = "stubfilter_precompiled",
    out = "stubfilter_precompiled.go",
    out_package_name = "ptrace",
    programs_to_compile_go_import = "gvisor.dev/gvisor/pkg/sentry/platform/ptrace/stubfilter",
    programs_to_compile_go_library = "//pkg/sentry/platform/ptrace/stubfilter",
)

go_library(
    name = "ptrace",
    srcs = [
        "filters.go",
        "ptrace.go",
        "ptrace_amd64.go",
        "ptrace_arm64.go",
        "ptrace_arm64_unsafe.go",
        "ptrace_unsafe.go",
        "stub_amd64.s",
        "stub_arm64.s",
        "stub_unsafe.go",
        "stubfilter_precompiled.go",
        "subprocess.go",
        "subprocess_amd64.go",
        "subprocess_arm64.go",
        "subprocess_linux.go",
        "subprocess_linux_unsafe.go",
        "subprocess_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/hosttid",
        "//pkg/log",
        "//pkg/safecopy",
        "//pkg/seccomp",
        "//pkg/seccomp/precompiledseccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/arch/fpu",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/interrupt",
        "//pkg/sentry/platform/ptrace/stubfilter",
        "//pkg/sighandling",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "ptrace_test",
    size = "small",
    srcs = ["stubfilter_test.go"],
    embed = [":ptrace"],
    deps = ["//pkg/sentry/platform/ptrace/stubfilter"],
)
