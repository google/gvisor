load("@bazel_lib//lib:transitions.bzl", "platform_transition_filegroup")
load("@bazel_skylib//rules/directory:glob.bzl", "directory_glob")
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

config_setting(
    name = "musl",
    constraint_values = ["@llvm//constraints/libc:musl"],
)

# The BSD queue macros in LLVM's GNU sysroot have no libc dependencies.
# Select that header under GNU while keeping the plugin on musl.
directory_glob(
    name = "gnu_queue_header",
    srcs = ["sys/queue.h"],
    directory = "@llvm//runtimes/glibc:glibc_headers_include_search_directory",
    tags = ["manual"],  # Select through the GNU transition below.
)

platform_transition_filegroup(
    name = "amd64_queue_header",
    srcs = [":gnu_queue_header"],
    target_platform = "@llvm//platforms:linux_x86_64",
)

cc_library(
    name = "bsd_queue",
    hdrs = [":amd64_queue_header"],
    include_prefix = "sys",
    strip_include_prefix = "/include/sys",
)

# The existing plugin supports Linux AMD64; DPDK also runs helper executables
# during its build, so its execution platform must match that architecture.
make(
    name = "libpluginstack",
    # DPDK takes tools and flags as command-line variables. Capture the
    # foreign_cc environment before its recursive makefiles redefine them.
    args = [
        "'CC:=$(CC)'",
        "'CPP:=$(CC) -E'",
        "'AR:=$(AR)'",
        # DPDK combines driver objects with a raw relocatable link.
        "'LD:=$(if $(filter /%,$(DPDK_LD)),$(DPDK_LD),$(EXT_BUILD_ROOT)/$(DPDK_LD))'",
        "'OBJDUMP:=$(if $(filter /%,$(OBJDUMP)),$(OBJDUMP),$(EXT_BUILD_ROOT)/$(OBJDUMP))'",
        "'TOOLCHAIN_CFLAGS:=$(CFLAGS)'",
        "'TOOLCHAIN_LDFLAGS:=$(LDFLAGS)'",
        "'HOST_EXTRA_CFLAGS:=$(CFLAGS)'",
        "'HOST_EXTRA_CPPFLAGS:=$(CPPFLAGS)'",
        "'EXTRA_HOST_LDFLAGS:=$(LDFLAGS)'",
        "'DPDK_TARGET:=$(RTE_TARGET)'",
        "DPDK_MACHINE=ivb",
        # The VFIO driver calls pread64 and pwrite64.
        "EXTRA_CPPFLAGS=-D_LARGEFILE64_SOURCE",
        "EXTRA_CFLAGS='-g -O3 -fPIC -fno-omit-frame-pointer -DLOOK_ASIDE_BACKEND -Wno-error'",
    ],
    build_data = [
        "@plugin_dpdk//:Makefile",
        "@plugin_dpdk//:sources",
        "@llvm//tools:ld.lld",
        "@llvm//tools:llvm-objdump",
    ],
    env = {
        "DPDK_LD": "$(execpath @llvm//tools:ld.lld)",
        "DPDK_MAKEFILE": "$(execpath @plugin_dpdk//:Makefile)",
        "OBJDUMP": "$(execpath @llvm//tools:llvm-objdump)",
        "RTE_TARGET": "x86_64-native-linuxapp-$(C_COMPILER)",
    },
    exec_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:linux",
    ],
    # DPDK executes build helpers on hosts without a musl interpreter.
    features = select({
        ":musl": ["fully_static_link"],
        "//conditions:default": [],
    }),
    lib_source = ":sources",
    out_static_libs = ["libpluginstack.a"],
    postfix_script = """
mkdir -p $$INSTALLDIR/lib $$INSTALLDIR/include
cp -L libtldk.a $$INSTALLDIR/lib/libpluginstack.a
""",
    target_compatible_with = select({
        ":plugin_tldk_condition": [
            "@platforms//cpu:x86_64",
            "@platforms//os:linux",
        ],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    targets = ["libtldk.a"],
    visibility = ["//visibility:public"],
    deps = select({
        ":musl": [":bsd_queue"],
        "//conditions:default": [],
    }),
)
