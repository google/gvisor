load("@bazel_skylib//rules:write_file.bzl", "write_file")
load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

package(default_visibility = ["//visibility:public"])

# fsstress uses only these configure checks. Both supported Linux libc
# toolchains provide prctl and the GNU struct file_handle definition.
write_file(
    name = "config",
    out = "include/config.h",
    content = [
        "#define HAVE_STRUCT_FILE_HANDLE 1",
        "#define HAVE_SYS_PRCTL_H 1",
    ],
)

cc_binary(
    name = "fsstress",
    srcs = [
        "include/lapi/fcntl.h",
        "include/tst_common.h",
        "testcases/kernel/fs/fsstress/fsstress.c",
        "testcases/kernel/fs/fsstress/global.h",
        "testcases/kernel/fs/fsstress/xfscompat.h",
        ":config",
    ],
    copts = ["-O2"],
    includes = ["include"],
    # fsstress does not load plugins. Static linkage lets it run on the
    # BusyBox image without installing the build toolchain's libc.
    linkopts = ["-static"],
    # Match upstream's standalone target, which does not exercise XFS ioctls.
    local_defines = [
        "NO_XFS",
        "_LARGEFILE64_SOURCE",
    ],
    # fsstress exercises Linux filesystem and process-control interfaces.
    target_compatible_with = ["@platforms//os:linux"],
)

exports_files(["COPYING"])
