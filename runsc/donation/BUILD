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
    ],
)
