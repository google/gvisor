load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_foreign_cc//foreign_cc:defs.bzl", "make")

exports_files(glob(["dpdk/dpdk-v18.11_patches/*.patch"]))

filegroup(
    name = "sources",
    srcs = [
        "Makefile",
        "dpdk/Makefile",
    ] + glob([
        "lib/**",
        "mk/**",
    ]),
)

config_setting(
    name = "plugin_tldk_condition",
    values = {"define": "plugin_tldk=true"},
)

copy_file(
    name = "queue_header",
    src = "@plugin_bsd_queue//file",
    out = "include/sys/queue.h",
)

cc_library(
    name = "bsd_queue",
    hdrs = [":queue_header"],
    includes = ["include"],
)

# The existing plugin supports Linux AMD64; DPDK also runs helper executables
# during its build, so its execution platform must match that architecture.
make(
    name = "libpluginstack",
    args = [
        "DPDK_MACHINE=ivb",
        "EXTRA_CFLAGS='-g -O3 -fPIC -fno-omit-frame-pointer -DLOOK_ASIDE_BACKEND -Wno-error'",
    ],
    build_data = [
        "@plugin_dpdk//:Makefile",
        "@plugin_dpdk//:sources",
    ],
    env = {
        "DPDK_MAKEFILE": "$(execpath @plugin_dpdk//:Makefile)",
        "OBJDUMP": "$(PLUGIN_OBJDUMP)",
        "RTE_TARGET": "x86_64-native-linuxapp-$(C_COMPILER)",
    },
    exec_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:linux",
    ],
    # Build-time helpers must also run on workers without a musl interpreter.
    features = ["fully_static_link"],
    lib_source = ":sources",
    out_static_libs = ["libpluginstack.a"],
    resource_size = "small",
    target_compatible_with = select({
        ":plugin_tldk_condition": [
            "@platforms//cpu:x86_64",
            "@platforms//os:linux",
        ],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    targets = ["install-plugin"],
    toolchains = ["@//external/tools/plugin-stack:toolchain"],
    visibility = ["//visibility:public"],
    deps = [
        ":bsd_queue",
        "@libbacktrace//:backtrace",
    ],
)
