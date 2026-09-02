load("//tools:defs.bzl", "cc_flags_supplier", "cc_toolchain", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# Tell build_cleaner not to create an unnecessary cc_library for
# fdparking.c.
filegroup(
    name = "ignore_srcs",
    srcs = ["fdparking.c"],
    tags = ["ignore_srcs"],
)

# runsc-fd-parking must remain a statically-linked, freestanding
# (no libc) C binary. It exists for the lifetime of each sandbox just to hold
# some FDs, so its runtime memory footprint *must* stay absolutely minimal.
genrule(
    name = "runsc-fd-parking",
    srcs = ["fdparking.c"],
    outs = ["runsc-fd-parking"],
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
          "-Wl,-z,max-page-size=65536 " +
          "-Wl,-z,noseparate-code " +
          "-o $(location runsc-fd-parking) " +
          "$(location fdparking.c)",
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
    name = "fdparking_test",
    size = "small",
    srcs = ["fdparking_test.go"],
    data = [":runsc-fd-parking"],
    deps = [
        "//pkg/test/testutil",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
