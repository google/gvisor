package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

go_library(
    name = "ashmem",
    srcs = [
        "area.go",
        "device.go",
        "pin_board.go",
        "uint64_range.go",
        "uint64_set.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/ashmem",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/tmpfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
    ],
)

go_test(
    name = "ashmem_test",
    size = "small",
    srcs = ["pin_board_test.go"],
    embed = [":ashmem"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/usermem",
    ],
)

go_template_instance(
    name = "uint64_range",
    out = "uint64_range.go",
    package = "ashmem",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uint64",
    },
)

go_template_instance(
    name = "uint64_set",
    out = "uint64_set.go",
    package = "ashmem",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "Range",
        "Value": "noValue",
        "Functions": "setFunctions",
    },
)
