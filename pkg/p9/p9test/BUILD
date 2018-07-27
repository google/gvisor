package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_test(
    name = "p9test_test",
    size = "small",
    srcs = ["client_test.go"],
    embed = [":p9test"],
    deps = [
        "//pkg/fd",
        "//pkg/p9",
        "//pkg/unet",
    ],
)

go_library(
    name = "p9test",
    srcs = [
        "mocks.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/p9/p9test",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/fd",
        "//pkg/p9",
    ],
)
