load("@io_bazel_rules_go//go:def.bzl", "go_embed_data")

package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_embed_data(
    name = "vdso_bin",
    src = "//vdso:vdso.so",
    package = "loader",
    var = "vdsoBin",
)

go_library(
    name = "loader",
    srcs = [
        "elf.go",
        "interpreter.go",
        "loader.go",
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
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/limits",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
