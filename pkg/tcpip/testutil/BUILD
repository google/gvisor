load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "testutil",
    testonly = True,
    srcs = [
        "testutil.go",
        "testutil_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/testutil",
    visibility = ["//visibility:public"],
    deps = ["//pkg/tcpip"],
)

go_test(
    name = "testutil_test",
    srcs = ["testutil_test.go"],
    embed = [":testutil"],
    deps = ["//pkg/tcpip"],
)
