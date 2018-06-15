package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_embed_data", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_embed_data(
    name = "vdso_bin",
    src = "//vdso:vdso.so",
    package = "loader",
    var = "vdsoBin",
)

go_stateify(
    name = "loader_state",
    srcs = [
        "vdso.go",
        "vdso_state.go",
    ],
    out = "loader_state.go",
    package = "loader",
)

go_library(
    name = "loader",
    srcs = [
        "elf.go",
        "interpreter.go",
        "loader.go",
        "loader_state.go",
        "vdso.go",
        "vdso_state.go",
        ":vdso_bin",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/loader",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi",
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/cpuid",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/refs",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/limits",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
