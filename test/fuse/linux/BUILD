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
        ":fuse_base",
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

cc_library(
    name = "fuse_base",
    testonly = 1,
    srcs = ["fuse_base.cc"],
    hdrs = ["fuse_base.h"],
    deps = [
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_util",
        "@com_google_absl//absl/strings:str_format",
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
