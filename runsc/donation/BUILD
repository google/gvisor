load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "donation",
    srcs = [
        "donation.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
