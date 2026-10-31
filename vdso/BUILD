# Description:
#   This VDSO is a shared library that provides the same interfaces as the
#   normal system VDSO (time, gettimeofday, clock_gettimeofday) but which uses
#   timekeeping parameters managed by the sandbox kernel.

load("@rules_python//python:py_test.bzl", "py_test")
load("//tools:arch.bzl", "select_arch")
load("//tools:defs.bzl", "cc_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

exports_files(["check_vdso.py"])

filegroup(
    name = "linker_script",
    srcs = select_arch(
        amd64 = ["vdso_amd64.lds"],
        arm64 = ["vdso_arm64.lds"],
        no_match_error = "unsupported architecture",
    ),
)

cc_binary(
    name = "vdso.so",
    srcs = [
        "barrier.h",
        "compiler.h",
        "cycle_clock.h",
        "seqlock.h",
        "syscalls.h",
        "vdso.cc",
        "vdso_time.cc",
        "vdso_time.h",
    ],
    additional_linker_inputs = [":linker_script"],
    copts = [
        "-O2",
        "-std=c++11",
        "-fPIC",
        "-fno-sanitize=all",
        # Some toolchains enable stack protector by default. Disable it, the
        # VDSO has no hooks to handle failures.
        "-fno-stack-protector",
    ],
    features = [
        "-coverage",
        "-default_link_flags",
        "-pie",
    ],
    link_extra_lib = None,
    linkopts = [
        "-nostdlib",
        "-Wl,-soname=linux-vdso.so.1",
        "-Wl,--hash-style=sysv",
        "-Wl,--no-undefined",
        "-Wl,-Bsymbolic",
        "-Wl,-z,max-page-size=4096",
        "-Wl,-z,common-page-size=4096",
        "-Wl,-T,$(location :linker_script)",
    ],
    linkshared = True,
    linkstatic = True,
    stamp = 0,
    visibility = ["//:sandbox"],
)

alias(
    name = "vdso",
    actual = ":vdso.so",
    visibility = ["//:sandbox"],
)

py_test(
    name = "vdso_test",
    srcs = ["check_vdso.py"],
    args = [
        "--check-data",
        "--vdso=$(location :vdso)",
    ],
    data = [":vdso"],
    main = "check_vdso.py",
)
