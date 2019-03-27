# Description:
#   This VDSO is a shared library that provides the same interfaces as the
#   normal system VDSO (time, gettimeofday, clock_gettimeofday) but which uses
#   timekeeping parameters managed by the sandbox kernel.

package(licenses = ["notice"])

config_setting(
    name = "x86_64",
    constraint_values = ["@bazel_tools//platforms:x86_64"],
)

genrule(
    name = "vdso",
    srcs = [
        "barrier.h",
        "compiler.h",
        "cycle_clock.h",
        "seqlock.h",
        "syscalls.h",
        "vdso.cc",
        "vdso.lds",
        "vdso_time.h",
        "vdso_time.cc",
    ],
    outs = [
        "vdso.so",
    ],
    cmd = "$(CC) $(CC_FLAGS) " +
          "-I. " +
          "-O2 " +
          "-std=c++11 " +
          "-fPIC " +
          # Some toolchains enable stack protector by default. Disable it, the
          # VDSO has no hooks to handle failures.
          "-fno-stack-protector " +
          "-fuse-ld=gold " +
          select({
              ":x86_64": "-m64 ",
              "//conditions:default": "",
          }) +
          "-shared " +
          "-nostdlib " +
          "-Wl,-soname=linux-vdso.so.1 " +
          "-Wl,--hash-style=sysv " +
          "-Wl,--no-undefined " +
          "-Wl,-Bsymbolic " +
          "-Wl,-z,max-page-size=4096 " +
          "-Wl,-z,common-page-size=4096 " +
          "-Wl,-T$(location vdso.lds) " +
          "-o $(location vdso.so) " +
          "$(location vdso.cc) " +
          "$(location vdso_time.cc) " +
          "&& $(location :check_vdso) " +
          "--check-data " +
          "--vdso $(location vdso.so) ",
    features = ["-pie"],
    toolchains = [
        "@bazel_tools//tools/cpp:current_cc_toolchain",
        "@bazel_tools//tools/cpp:cc_flags",
    ],
    tools = [
        ":check_vdso",
    ],
    visibility = ["//:sandbox"],
)

py_binary(
    name = "check_vdso",
    srcs = ["check_vdso.py"],
    visibility = ["//:sandbox"],
)
