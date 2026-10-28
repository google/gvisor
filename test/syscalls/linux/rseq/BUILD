# This package contains a standalone rseq test binary. This binary must not
# depend on libc, which might use rseq itself.

load("//tools:arch.bzl", "select_arch")
load("//tools:defs.bzl", "cc_binary", "cc_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

cc_binary(
    name = "rseq",
    testonly = True,
    srcs = [
        "critical.h",
        "rseq.cc",
        "syscalls.h",
        "test.h",
        "types.h",
        "uapi.h",
    ] + select_arch(
        amd64 = [
            "critical_amd64.S",
            "start_amd64.S",
        ],
        arm64 = [
            "critical_arm64.S",
            "start_arm64.S",
        ],
        no_match_error = "unsupported architecture",
    ),
    copts = [
        "-Wall",
        "-Werror",
        "-O2",
        "-ffreestanding",
        "-fno-exceptions",
        "-fno-stack-protector",
    ],
    features = [
        "-coverage",
        "-default_link_flags",
        "-pie",
    ],
    link_extra_lib = None,
    linkopts = [
        "-static",
        "-nostdlib",
    ],
    linkstatic = True,
    stamp = 0,
    visibility = ["//:sandbox"],
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
