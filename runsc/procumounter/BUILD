load("//tools:defs.bzl", "cc_flags_supplier", "cc_toolchain", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# Tell build_cleaner not to create an unnecessary cc_library for
# procumounter.c.
filegroup(
    name = "ignore_srcs",
    srcs = ["procumounter.c"],
    tags = ["ignore_srcs"],
)

# gvisor-proc-umounter must remain a statically-linked, freestanding (no libc)
# C binary that fits in a single 4KiB page. Read its comments as to why.
genrule(
    name = "procumounter_binary",
    srcs = ["procumounter.c"],
    outs = ["gvisor-proc-umounter"],
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
          "-o $(execpath gvisor-proc-umounter) " +
          "$(execpath procumounter.c)",
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
    name = "procumounter_test",
    size = "small",
    srcs = ["procumounter_test.go"],
    data = [":procumounter_binary"],
    deps = [
        "//pkg/test/testutil",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
