load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "wire",
    srcs = ["wire.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire",
    marshal = True,
    visibility = ["//:sandbox"],
)

go_test(
    name = "wire_test",
    size = "small",
    srcs = ["wire_test.go"],
    embed = [":wire"],
)
