load("//tools:arch.bzl", "arch_genrule", "select_arch")
load("//tools:defs.bzl", "cc_binary", "cc_toolchain", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# The stub runs inside a sandboxed process. It has no C runtime and must
# contain only position-independent code and data in the layout in pie.lds.S.
cc_binary(
    name = "sighandler.built-in.bin.o",
    srcs = [
        "atomic.h",
        "sysmsg.h",
        "sysmsg_lib.c",
        "sysmsg_offsets.h",
    ] + select_arch(
        amd64 = [
            "sighandler_amd64.c",
            "sigrestorer_amd64.S",
            "syshandler_amd64.S",
            "sysmsg_offsets_amd64.h",
        ],
        arm64 = [
            "sighandler_arm64.c",
            "sigrestorer_arm64.S",
            "syshandler_arm64.S",
        ],
    ),
    additional_linker_inputs = ["pie.lds.S"],
    copts = [
        "-Wall",
        "-Werror",
        "-Wno-unused-command-line-argument",
        "-fpie",
        "-fno-builtin",
        "-ffreestanding",
        "-mgeneral-regs-only",
        # pie.lds.S folds .debug* into the .crblob bytes Go embeds. Keep
        # DWARF's build paths out of the mapped stub.
        "-g0",
        "-Wa,--noexecstack",
        "-fno-asynchronous-unwind-tables",
        "-fno-sanitize=all",
        "-fno-stack-protector",
    ] + select_arch(
        amd64 = ["-O2"],
        arm64 = [
            # Keep the original ARM64 level. Unoptimized Clang emitted a
            # memcpy call for a struct copy before the stub provided memcpy.
            # That history doesn't establish a need for -O1 over -O2.
            "-O1",
            "-mno-outline-atomics",
        ],
    ),
    features = [
        "-coverage",
        "-default_link_flags",
        "-pie",
    ],
    link_extra_lib = None,
    linkopts = [
        "-nostdlib",
        "-pie",
        "-Wl,--build-id=none",
        # Go locates __export_ symbols that the stub itself need not reference.
        "-Wl,--no-gc-sections",
        "-Wl,-z,noexecstack",
        "-Wl,-T,$(location pie.lds.S)",
    ],
    linkstatic = True,
    local_defines = select({
        "//tools/bazeldefs:pagesize_64k": ["PAGE_SIZE=65536"],
        "//conditions:default": ["PAGE_SIZE=4096"],
    }),
    stamp = 0,
)

alias(
    name = "sighandler_object",
    actual = ":sighandler.built-in.bin.o",
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
    outs = ["sighandler.go.arch"],
    cmd = "bash -x $(location gen_offsets_go.sh) sighandler Sighandler " +
          "$(SRCS) \"$(NM)\" > $@",
    toolchains = [cc_toolchain],
    tools = ["gen_offsets_go.sh"],
)

arch_genrule(
    name = "sighandler_go_arch",
    src = ":sighandler_go",
    template = "sighandler_%s.go",
)

go_library(
    name = "sysmsg",
    srcs = [
        "sysmsg.go",
        "sysmsg_4k.go",
        "sysmsg_64k.go",
        "sysmsg_amd64.go",
        "sysmsg_arm64.go",
        "sysmsg_unsafe.go",
        ":sighandler_go_arch",
    ],
    embedsrcs = [
        ":sighandler_binary_arch",  # keep
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/hostsyscall",
        "//pkg/sentry/platform",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
