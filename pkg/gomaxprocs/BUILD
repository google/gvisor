load("//pkg/sync/locking:locking.bzl", "declare_mutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "gomaxprocs_mutex",
    out = "gomaxprocs_mutex.go",
    package = "gomaxprocs",
    prefix = "gomaxprocs",
)

go_library(
    name = "gomaxprocs",
    srcs = [
        "gomaxprocs.go",
        "gomaxprocs_mutex.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sync",
        "//pkg/sync/locking",
    ],
)

go_test(
    name = "gomaxprocs_test",
    size = "small",
    srcs = ["gomaxprocs_test.go"],
    library = ":gomaxprocs",
)
