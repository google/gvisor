load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "wire",
    srcs = ["wire.go"],
    importpath = "gvisor.dev/gvisor/pkg/state/wire",
    marshal = False,
    stateify = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/gohacks",
    ],
)

go_test(
    name = "wire_test",
    srcs = ["wire_test.go"],
    embed = [":wire"],
)
