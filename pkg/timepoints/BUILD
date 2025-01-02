load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "timepoints_test",
    srcs = ["timepoints_test.go"],
    library = ":timepoints",
    deps = ["//pkg/sync"],
)

go_library(
    name = "timepoints",
    srcs = ["timepoints.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/bitmap",
        "//pkg/gohacks",
        "//pkg/log",
        "//pkg/sync",
    ],
)
