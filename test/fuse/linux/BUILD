load("//tools:defs.bzl", "cc_binary", "cc_library", "gtest")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

cc_binary(
    name = "stat_test",
    testonly = 1,
    srcs = ["stat_test.cc"],
    deps = [
        gtest,
        ":fuse_fd_util",
        "//test/util:cleanup",
        "//test/util:fs_util",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "statfs_test",
    testonly = 1,
    srcs = ["statfs_test.cc"],
    deps = [
        gtest,
        ":fuse_fd_util",
        "//test/util:cleanup",
        "//test/util:fs_util",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "open_test",
    testonly = 1,
    srcs = ["open_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "release_test",
    testonly = 1,
    srcs = ["release_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "mknod_test",
    testonly = 1,
    srcs = ["mknod_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fuse_util",
        "//test/util:temp_umask",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "symlink_test",
    testonly = 1,
    srcs = ["symlink_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "readlink_test",
    testonly = 1,
    srcs = ["readlink_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "mkdir_test",
    testonly = 1,
    srcs = ["mkdir_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fuse_util",
        "//test/util:temp_umask",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "setstat_test",
    testonly = 1,
    srcs = ["setstat_test.cc"],
    deps = [
        gtest,
        ":fuse_fd_util",
        "//test/util:cleanup",
        "//test/util:fs_util",
        "//test/util:fuse_util",
        "//test/util:temp_umask",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "rmdir_test",
    testonly = 1,
    srcs = ["rmdir_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fs_util",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "readdir_test",
    testonly = 1,
    srcs = ["readdir_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fs_util",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_library(
    name = "fuse_base",
    testonly = 1,
    srcs = ["fuse_base.cc"],
    hdrs = ["fuse_base.h"],
    deps = [
        gtest,
        "//test/util:fuse_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_util",
        "//test/util:thread_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "fuse_fd_util",
    testonly = 1,
    srcs = ["fuse_fd_util.cc"],
    hdrs = ["fuse_fd_util.h"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fuse_util",
        "//test/util:posix_error",
    ],
)

cc_binary(
    name = "read_test",
    testonly = 1,
    srcs = ["read_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "write_test",
    testonly = 1,
    srcs = ["write_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fuse_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "create_test",
    testonly = 1,
    srcs = ["create_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fs_util",
        "//test/util:fuse_util",
        "//test/util:temp_umask",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "unlink_test",
    testonly = 1,
    srcs = ["unlink_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fuse_util",
        "//test/util:temp_umask",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "mount_test",
    testonly = 1,
    srcs = ["mount_test.cc"],
    deps = [
        gtest,
        ":fuse_base",
        "//test/util:fs_util",
        "//test/util:fuse_util",
        "//test/util:mount_util",
        "//test/util:temp_path",
        "//test/util:temp_umask",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)
