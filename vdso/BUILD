# Description:
#   This VDSO is a shared library that provides the same interfaces as the
#   normal system VDSO (time, gettimeofday, clock_gettimeofday) but which uses
#   timekeeping parameters managed by the sandbox kernel.

load("//tools:defs.bzl", "cc_flags_supplier", "cc_toolchain", "select_arch", "vdso_linker_option")

package(licenses = ["notice"])

exports_files(["check_vdso.py"])

genrule(
    name = "vdso",
    srcs = [
        "barrier.h",
        "compiler.h",
        "cycle_clock.h",
        "seqlock.h",
        "syscalls.h",
        "vdso.cc",
        "vdso_amd64.lds",
        "vdso_arm64.lds",
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
          "-fno-sanitize=all " +
          # Some toolchains enable stack protector by default. Disable it, the
          # VDSO has no hooks to handle failures.
          "-fno-stack-protector " +
          vdso_linker_option +
          select_arch(
              amd64 = "-m64 ",
              arm64 = "",
          ) +
          "-shared " +
          "-nostdlib " +
          "-Wl,-soname=linux-vdso.so.1 " +
          "-Wl,--hash-style=sysv " +
          "-Wl,--no-undefined " +
          "-Wl,-Bsymbolic " +
          "-Wl,-z,max-page-size=4096 " +
          "-Wl,-z,common-page-size=4096 " +
          select_arch(
              amd64 = "-Wl,-T$(location vdso_amd64.lds) ",
              arm64 = "-Wl,-T$(location vdso_arm64.lds) ",
              no_match_error = "unsupported architecture",
          ) +
          "-o $(location vdso.so) " +
          "$(location vdso.cc) " +
          "$(location vdso_time.cc)",
    features = ["-pie"],
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

py_test(
    name = "vdso_test",
    srcs = ["check_vdso.py"],
    args = [
        "--check-data",
        "--vdso=$(location :vdso)",
    ],
    data = [":vdso"],
    main = "check_vdso.py",
    python_version = "PY3",
)
