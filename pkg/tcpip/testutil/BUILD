load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "testutil",
    testonly = True,
    srcs = [
        "testutil.go",
        "testutil_unsafe.go",
    ],
    visibility = ["//visibility:public"],
    deps = ["//pkg/tcpip"],
)

go_test(
    name = "testutil_test",
    srcs = ["testutil_test.go"],
    library = ":testutil",
    deps = ["//pkg/tcpip"],
)
