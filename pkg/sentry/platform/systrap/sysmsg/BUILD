load("//tools:arch.bzl", "select_arch")
load("//tools:defs.bzl", "cc_flags_supplier", "cc_toolchain", "go_library")
load("build.bzl", "cc_pie_obj")

package(licenses = ["notice"])

cc_pie_obj(
    name = "sighandler",
    srcs = select_arch(
        amd64 = ["sighandler_amd64.c"],
        arm64 = ["sighandler_arm64.c"],
    ) + [
        "sysmsg.h",
        "sysmsg_offsets.h",
    ],
    outs = ["sighandler.o"],
    obj_src = select_arch(
        amd64 = "sighandler_amd64.c",
        arm64 = "sighandler_arm64.c",
    ),
)

cc_pie_obj(
    name = "sysmsg_lib",
    srcs = [
        "sysmsg.h",
        "sysmsg_lib.c",
        "sysmsg_offsets.h",
    ],
    outs = ["sysmsg_lib.o"],
    obj_src = "sysmsg_lib.c",
)

cc_pie_obj(
    name = "sysrestorer",
    srcs = select_arch(
        amd64 = ["sigrestorer_amd64.S"],
        arm64 = ["sigrestorer_arm64.S"],
    ),
    outs = ["sysrestorer.o"],
    obj_src = select_arch(
        amd64 = "sigrestorer_amd64.S",
        arm64 = "sigrestorer_arm64.S",
    ),
)

cc_pie_obj(
    name = "syshandler",
    srcs = select_arch(
        amd64 = ["syshandler_amd64.S"],
        arm64 = ["syshandler_arm64.S"],
    ) + [
        "sysmsg_offsets.h",
    ],
    outs = ["syshandler.o"],
    obj_src = select_arch(
        amd64 = "syshandler_amd64.S",
        arm64 = "syshandler_arm64.S",
    ),
)

genrule(
    name = "sighandler.built-in.object",
    srcs = [
        "pie.lds.S",
        ":sighandler",
        ":syshandler",
        ":sysrestorer",
        ":sysmsg_lib",
    ],
    outs = ["sighandler.built-in.bin.o"],
    cmd = "$(LD) " +
          "-o $(location sighandler.built-in.bin.o) " +
          "-pie -z noexecstack -T $(location pie.lds.S) " +
          "$(location :sysrestorer) $(location :sighandler) " +
          "$(location :syshandler) $(location :sysmsg_lib) ",
    features = ["-pie"],
    toolchains = [
        cc_toolchain,
    ],
)

genrule(
    name = "sighandler.built-in.binary",
    srcs = [
        "sighandler.built-in.bin.o",
        ":sighandler.built-in.object",
    ],
    outs = ["sighandler.built-in.bin"],
    cmd = "$(OBJCOPY)  -O binary " +
          "$(location :sighandler.built-in.object) $(location sighandler.built-in.bin) ",
    toolchains = [
        cc_toolchain,
    ],
)

genrule(
    name = "sighandler-golang",
    srcs = [
        "sighandler.built-in.bin",
        "sighandler.built-in.bin.o",
        ":sighandler.built-in.object",
    ],
    outs = ["sighandler.go"],
    cmd = "bash -x $(location gen_offsets_go.sh) sighandler Sighandler " +
          "$(location :sighandler.built-in.object) " +
          "> $(location sighandler.go) ",
    tools = [
        "gen_offsets_go.sh",
    ],
)

cc_flags_supplier(
    name = "no_pie_cc_flags",
    features = ["-pie"],
)

go_library(
    name = "sysmsg",
    srcs = [
        "sighandler.go",
        "sysmsg.go",
        "sysmsg_amd64.go",
        "sysmsg_arm64.go",
    ],
    embedsrcs = ["sighandler.built-in.bin"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
        "//pkg/atomicbitops",
        "//pkg/cpuid",
        "//pkg/errors",
        "//pkg/hostarch",
        "//pkg/sentry/arch",
        "//pkg/usermem",
    ],
)
