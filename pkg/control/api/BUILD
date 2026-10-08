load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "api",
    srcs = ["fs.go"],
    importpath = "gvisor.dev/gvisor/pkg/control/api",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/urpc",
    ],
)
