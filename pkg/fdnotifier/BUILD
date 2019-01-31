load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "fdnotifier",
    srcs = [
        "fdnotifier.go",
        "poll_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/fdnotifier",
    visibility = ["//:sandbox"],
    deps = ["//pkg/waiter"],
)
