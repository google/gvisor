# This package contains a standalone rseq test binary. This binary must not
# depend on libc, which might use rseq itself.

load("//tools:defs.bzl", "cc_flags_supplier", "cc_library", "cc_toolchain", "select_arch")

package(licenses = ["notice"])

genrule(
    name = "rseq_binary",
    srcs = [
        "critical.h",
        "critical_amd64.S",
        "critical_arm64.S",
        "rseq.cc",
        "syscalls.h",
        "start_amd64.S",
        "start_arm64.S",
        "test.h",
        "types.h",
        "uapi.h",
    ],
    outs = ["rseq"],
    cmd = "$(CC) " +
          "$(CC_FLAGS) " +
          "-I. " +
          "-Wall " +
          "-Werror " +
          "-O2 " +
          "-std=c++17 " +
          "-static " +
          "-nostdlib " +
          "-ffreestanding " +
          "-o " +
          "$(location rseq) " +
          select_arch(
              amd64 = "$(location critical_amd64.S) $(location start_amd64.S) ",
              arm64 = "$(location critical_arm64.S) $(location start_arm64.S) ",
              no_match_error = "unsupported architecture",
          ) +
          "$(location rseq.cc)",
    toolchains = [
        cc_toolchain,
        ":no_pie_cc_flags",
    ],
    visibility = ["//:sandbox"],
)

cc_flags_supplier(
    name = "no_pie_cc_flags",
    features = ["-pie"],
)

cc_library(
    name = "lib",
    testonly = 1,
    hdrs = [
        "test.h",
        "uapi.h",
    ],
    visibility = ["//:sandbox"],
)
