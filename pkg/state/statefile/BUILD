load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "statefile",
    srcs = ["statefile.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/compressio",
        "//pkg/state/wire",
    ],
)

go_test(
    name = "statefile_test",
    size = "small",
    srcs = ["statefile_test.go"],
    library = ":statefile",
    deps = ["//pkg/compressio"],
)
