load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "amutex",
    srcs = ["amutex.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/context",
        "//pkg/errors/linuxerr",
    ],
)

go_test(
    name = "amutex_test",
    size = "small",
    srcs = ["amutex_test.go"],
    library = ":amutex",
    deps = ["//pkg/sync"],
)
