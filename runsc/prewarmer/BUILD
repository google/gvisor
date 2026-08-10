load("//tools:defs.bzl", "cc_binary", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# gvisor-sentry-prewarmer must remain a statically-linked, freestanding (no libc),
# single-threaded C binary that fits in a single 4KiB page.
# Do NOT rewrite it in Go; it must be single-threaded.
# Read its comments as to why.
cc_binary(
    name = "gvisor-sentry-prewarmer",
    srcs = ["prewarmer.c"],
    copts = [
        "-Os",
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
    ],
    linkopts = [
        "-static",
        "-nostdlib",
        "-nostartfiles",
        "-Wl,--build-id=none",
        "-Wl,--gc-sections",
        "-Wl,-s",
    ],
    visibility = ["//visibility:public"],
)

go_test(
    name = "prewarmer_single_page_test",
    size = "small",
    srcs = ["prewarmer_single_page_test.go"],
    data = [":gvisor-sentry-prewarmer"],
    deps = ["//pkg/test/testutil"],
)

go_binary(
    name = "fdtable_expander",
    srcs = ["fdtable_expander.go"],
    pure = True,
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

go_test(
    name = "prewarmer_speedup_test",
    size = "small",
    srcs = ["prewarmer_speedup_test.go"],
    data = [
        ":fdtable_expander",
        ":gvisor-sentry-prewarmer",
        "//:release",
    ],
    deps = ["//pkg/test/testutil"],
)
