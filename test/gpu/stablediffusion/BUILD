load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "stablediffusion",
    testonly = 1,
    srcs = ["stablediffusion.go"],
    importpath = "gvisor.dev/gvisor/test/gpu/stablediffusion",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)
