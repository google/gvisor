load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "sleep",
    srcs = [
        "commit_amd64.s",
        "commit_asm.go",
        "commit_noasm.go",
        "sleep_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sleep",
    visibility = ["//:sandbox"],
)

go_test(
    name = "sleep_test",
    size = "medium",
    srcs = [
        "sleep_test.go",
    ],
    embed = [":sleep"],
)
