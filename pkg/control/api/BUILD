load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "api",
    srcs = ["fs.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/urpc",
    ],
)
