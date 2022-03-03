load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

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
