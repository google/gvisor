# This package contains a standalone rseq test binary. This binary must not
# depend on libc, which might use rseq itself.

load("@bazel_tools//tools/cpp:cc_flags_supplier.bzl", "cc_flags_supplier")
load("@rules_cc//cc:defs.bzl", "cc_library")

package(licenses = ["notice"])

genrule(
    name = "rseq_binary",
    srcs = [
        "critical.h",
        "critical.S",
        "rseq.cc",
        "syscalls.h",
        "start.S",
        "test.h",
        "types.h",
        "uapi.h",
    ],
    outs = ["rseq"],
    cmd = " ".join([
        "$(CC)",
        "$(CC_FLAGS) ",
        "-I.",
        "-Wall",
        "-Werror",
        "-O2",
        "-std=c++17",
        "-static",
        "-nostdlib",
        "-ffreestanding",
        "-o",
        "$(location rseq)",
        "$(location critical.S)",
        "$(location rseq.cc)",
        "$(location start.S)",
    ]),
    toolchains = [
        ":no_pie_cc_flags",
        "@bazel_tools//tools/cpp:current_cc_toolchain",
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
