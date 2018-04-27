package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "arch_state",
    srcs = [
        "arch.go",
        "arch_amd64.go",
        "arch_state_x86.go",
        "arch_x86.go",
        "auxv.go",
        "signal_amd64.go",
    ],
    out = "arch_state.go",
    package = "arch",
)

go_library(
    name = "arch",
    srcs = [
        "aligned.go",
        "arch.go",
        "arch_amd64.go",
        "arch_amd64.s",
        "arch_state.go",
        "arch_state_x86.go",
        "arch_x86.go",
        "auxv.go",
        "signal_act.go",
        "signal_amd64.go",
        "signal_info.go",
        "signal_stack.go",
        "stack.go",
        "syscalls_amd64.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/arch",
    visibility = ["//:sandbox"],
    deps = [
        ":registers_go_proto",
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/cpuid",
        "//pkg/log",
        "//pkg/sentry/context",
        "//pkg/sentry/limits",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
    ],
)

proto_library(
    name = "registers_proto",
    srcs = ["registers.proto"],
    visibility = ["//visibility:public"],
)

go_proto_library(
    name = "registers_go_proto",
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/arch/registers_go_proto",
    proto = ":registers_proto",
    visibility = ["//visibility:public"],
)
