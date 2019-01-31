load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "hostcpu",
    srcs = [
        "getcpu_amd64.s",
        "hostcpu.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/hostcpu",
    visibility = ["//:sandbox"],
)

go_test(
    name = "hostcpu_test",
    size = "small",
    srcs = ["hostcpu_test.go"],
    embed = [":hostcpu"],
)
