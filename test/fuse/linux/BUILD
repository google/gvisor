load("//tools:defs.bzl", "cc_library", "gtest")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

cc_library(
    name = "fuse_base",
    testonly = 1,
    srcs = [
        "fuse_base.h",
        "fuse_base.cc",
    ],
    deps = [
        gtest,
        "//test/util:posix_error",
        "//test/util:test_util",
        "@com_google_absl//absl/strings:str_format",
    ],
)
