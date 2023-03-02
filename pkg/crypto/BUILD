load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "crypto",
    srcs = [
        "crypto.go",
        "crypto_stdlib.go",
    ],
    visibility = ["//:sandbox"],
)
