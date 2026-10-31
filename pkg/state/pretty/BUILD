load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "pretty",
    srcs = ["pretty.go"],
    importpath = "gvisor.dev/gvisor/pkg/state/pretty",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/state",
        "//pkg/state/wire",
    ],
)

go_test(
    name = "pretty_test",
    size = "small",
    srcs = ["pretty_test.go"],
    embed = [":pretty"],
    deps = [
        "//pkg/state",
        "//pkg/state/wire",
    ],
)
