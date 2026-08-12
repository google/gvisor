load("//tools:defs.bzl", "cc_flags_supplier", "cc_toolchain", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# Tell build_cleaner not to create an unnecessary cc_library for prewarmer.c.
filegroup(
    name = "ignore_srcs",
    srcs = ["prewarmer.c"],
    tags = ["ignore_srcs"],
)

# gvisor-sentry-prewarmer must remain a statically-linked, freestanding (no libc),
# single-threaded C binary that fits in a single 4KiB page.
# Do NOT rewrite it in Go; it must be single-threaded.
# Read its comments as to why.
genrule(
    name = "gvisor-sentry-prewarmer",
    srcs = ["prewarmer.c"],
    outs = ["gvisor-sentry-prewarmer"],
    cmd = "$(CC) $(CC_FLAGS) " +
          "-Os " +
          "-ffreestanding " +
          "-fno-sanitize=all " +
          "-fno-stack-protector " +
          "-fno-asynchronous-unwind-tables " +
          "-fno-unwind-tables " +
          "-static " +
          "-nostdlib " +
          "-nostartfiles " +
          "-Wl,--build-id=none " +
          "-Wl,--gc-sections " +
          "-Wl,-s " +
          "-Wl,-n " +
          "-o $(location gvisor-sentry-prewarmer) " +
          "$(location prewarmer.c)",
    executable = True,
    features = ["-pie"],
    toolchains = [
        cc_toolchain,
        ":no_pie_cc_flags",
    ],
    visibility = ["//visibility:public"],
)

cc_flags_supplier(
    name = "no_pie_cc_flags",
    features = ["-pie"],
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
