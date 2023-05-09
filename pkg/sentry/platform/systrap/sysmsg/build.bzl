"""Sysmsg rules."""

load("//tools:arch.bzl", "select_arch")
load("//tools:defs.bzl", "cc_toolchain")

def cc_pie_obj(name, srcs, outs):
    native.genrule(
        name = name,
        srcs = srcs,
        outs = outs,
        cmd = "$(CC)  $(CC_FLAGS)  " +
              "-Wall -Werror -Wno-unused-command-line-argument " +
              "-fpie " +
              # -01 is required for clang to avoid making use of memcpy when
              # building for ARM64. For some reason when no optimization is turned
              # on clang makes use of memcpy to copy structures and when combined
              # with -ffreestanding it means we need to provide our own version of
              # memcpy. Using -01 causes clang to not make use of memcpy avoiding
              # the need to supply our own memcpy version.
              select_arch(
                  amd64 = "-O2",
                  arm64 = "-O1 -mno-outline-atomics ",
              ) +
              " -fno-builtin " +
              "-ffreestanding " +
              "-g " +
              "-Wa,--noexecstack " +
              "-fno-asynchronous-unwind-tables " +
              "-fno-stack-protector " +
              "-c $$(echo $(SRCS) | tr ' ' '\n' | grep -v -E '.h$$') -o $@",
        toolchains = [
            ":no_pie_cc_flags",
            cc_toolchain,
        ],
    )
