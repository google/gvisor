# setup_container starts the syscall test runner. For container=True tests,
# it also prepares the network inside the test container.

load("//tools:defs.bzl", "cc_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

cc_binary(
    name = "setup_container",
    testonly = 1,
    srcs = ["setup_container.cc"],
    visibility = ["//:sandbox"],
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:posix_error",
        "//test/util:socket_util",
    ],
)
