load("//tools:defs.bzl", "go_library", "proto_library")

package(licenses = ["notice"])

go_library(
    name = "arch",
    srcs = [
        "aligned.go",
        "arch.go",
        "arch_aarch64.go",
        "arch_amd64.go",
        "arch_arm64.go",
        "arch_state_x86.go",
        "arch_x86.go",
        "arch_x86_impl.go",
        "auxv.go",
        "signal.go",
        "signal_amd64.go",
        "signal_arm64.go",
        "signal_info.go",
        "stack.go",
        "stack_unsafe.go",
        "syscalls_amd64.go",
        "syscalls_arm64.go",
    ],
    marshal = True,
    visibility = ["//:sandbox"],
    deps = [
        ":registers_go_proto",
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/sentry/arch/fpu",
        "//pkg/sentry/limits",
        "//pkg/syserror",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

proto_library(
    name = "registers",
    srcs = ["registers.proto"],
    visibility = ["//visibility:public"],
)
