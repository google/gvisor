load("//tools:arch.bzl", "arch_genrule", "select_arch")
load("//tools:defs.bzl", "cc_flags_supplier", "cc_toolchain", "go_embed_data", "go_library")

package(licenses = ["notice"])

cc_flags_supplier(
    name = "no_pie_cc_flags",
    features = ["-pie"],
)

genrule(
    name = "sighandler_object",
    srcs = [
        "pie.lds",
        "sighandler_amd64.c",
        "sighandler_arm64.c",
        "sysmsg.h",
        "sysmsg_lib.c",
        "sysmsg_offsets.h",
        "syshandler_amd64.S",
        "syshandler_arm64.S",
        "sigrestorer_amd64.S",
        "sigrestorer_arm64.S",
    ],
    outs = ["sighandler.built-in.bin.o"],
    cmd = "$(CC) $(CC_FLAGS)  " +
          "-fpie -z noexecstack -T $(location pie.lds) " +
          # -01 is required for clang to avoid making use of memcpy when
          # building for ARM64. For some reason when no optimization is turned
          # on clang makes use of memcpy to copy structures and when combined
          # with -ffreestanding it means we need to provide our own version of
          # memcpy. Using -01 causes clang to not make use of memcpy avoiding
          # the need to supply our own memcpy version.
          select_arch(
              amd64 = "-O2 ",
              arm64 = "-O1 -mno-outline-atomics ",
          ) +
          "-fno-builtin " +
          "-ffreestanding " +
          "-nostdlib " +
          "-g " +
          "-Wl,--build-id=none " +
          "-Wa,--noexecstack " +
          "-fno-asynchronous-unwind-tables " +
          "-fno-stack-protector " +
          "$$(echo $(SRCS) | tr ' ' '\n' | grep -E '.[Sc]$$') -o $@",
    features = ["-pie"],
    toolchains = [
        ":no_pie_cc_flags",
        cc_toolchain,
    ],
)

genrule(
    name = "sighandler_binary",
    srcs = [":sighandler_object"],
    outs = ["sighandler.built-in.bin"],
    cmd = "$(OBJCOPY) -O binary $(SRCS) $@",
    toolchains = [
        cc_toolchain,
    ],
)

arch_genrule(
    name = "sighandler_binary_arch",
    src = ":sighandler_binary",
    template = "sighandler.built-in.%s.bin",
)

genrule(
    name = "sighandler_go",
    srcs = [":sighandler_object"],
    outs = ["sighandler.go"],
    cmd = "bash -x $(location gen_offsets_go.sh) sighandler Sighandler " +
          "$(SRCS) > $@",
    tools = ["gen_offsets_go.sh"],
)

arch_genrule(
    name = "sighandler_go_arch",
    src = ":sighandler_go",
    template = "sighandler_%s.go",
)

go_embed_data(
    name = "sighandler_data",
    src = ":sighandler_binary",
    package = "sysmsg",
    var = "SighandlerBlob",
)

arch_genrule(
    name = "sighandler_data_arch",
    src = ":sighandler_data",
    template = "sighandlerdata_%s.go",
)

go_library(
    name = "sysmsg",
    srcs = [
        "sysmsg.go",
        "sysmsg_amd64.go",
        "sysmsg_arm64.go",
        ":sighandler_data_arch",
        ":sighandler_go_arch",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
        "//pkg/cpuid",
        "//pkg/errors",
        "//pkg/hostarch",
    ],
)
