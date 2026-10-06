load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "errno",
    srcs = ["errno.go"],
    hostlayout = True,
    importpath = "gvisor.dev/gvisor/pkg/abi/linux/errno",
    visibility = ["//visibility:public"],
)
