load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "nlmsg",
    srcs = [
        "message.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/hostarch",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
    ],
)

go_test(
    name = "nlmsg_test",
    size = "small",
    srcs = [
        "message_test.go",
    ],
    deps = [
        ":nlmsg",
        "//pkg/abi/linux",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
    ],
)
