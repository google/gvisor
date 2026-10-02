load("//tools:defs.bzl", "cc_binary", "cc_flags_supplier", "cc_toolchain", "go_binary", "go_test")

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
    name = "prewarmer_binary",
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
          "-o $(execpath gvisor-sentry-prewarmer) " +
          "$(execpath prewarmer.c)",
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
    data = [":prewarmer_binary"],
    deps = ["//pkg/test/testutil"],
)

go_binary(
    name = "fdtable_expander",
    srcs = ["fdtable_expander.go"],
    pure = True,
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

cc_binary(
    name = "exec_fd_helper",
    testonly = 1,
    srcs = ["exec_fd_helper.c"],
)

go_test(
    name = "prewarmer_speedup_test",
    size = "small",
    srcs = ["prewarmer_speedup_test.go"],
    data = [
        ":exec_fd_helper",
        ":fdtable_expander",
        ":prewarmer_binary",
        "//:release",
    ],
    deps = ["//pkg/test/testutil"],
)
