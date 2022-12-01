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
    marshal = True,
    marshal_debug = True,
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi",
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/safemem",
        "//pkg/sentry/arch",
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
        "//pkg/usermem",
    ],
)
