load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "loader",
    srcs = [
        "elf.go",
        "interpreter.go",
        "loader.go",
        "vdso.go",
        "vdso_state.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi",
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsbridge",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/limits",
        "//pkg/sentry/loader/vdsodata",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)
