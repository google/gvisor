load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "cuda",
    testonly = True,
    srcs = ["cuda.go"],
    visibility = ["//test/gpu:__subpackages__"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)
