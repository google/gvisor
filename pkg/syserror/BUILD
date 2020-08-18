load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "syserror",
    srcs = ["syserror.go"],
    visibility = ["//visibility:public"],
)

go_test(
    name = "syserror_test",
    srcs = ["syserror_test.go"],
    deps = [
        ":syserror",
    ],
)
