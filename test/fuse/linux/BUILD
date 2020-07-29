load("//tools:defs.bzl", "cc_library", "gtest")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

cc_test(
    name = "stat_test",
    srcs = [
        "fuse_base.h",
        "stat_test.cc",
    ],
    deps = [
        ":fuse_base",
        "//test/util:test_util",
        "//test/util:test_main",
    ],
)

cc_library(
    name = "fuse_base",
    testonly = 1,
    srcs = [
        "fuse_base.cc",
        "fuse_base.h",
    ],
    deps = [
        gtest,
        "//test/util:posix_error",
        "//test/util:test_util",
        "@com_google_absl//absl/strings:str_format",
    ],
)
