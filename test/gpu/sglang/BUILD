load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sglang",
    testonly = 1,
    srcs = ["sglang.go"],
    importpath = "gvisor.dev/gvisor/test/gpu/sglang",
    stateify = False,  # Does not support some generics methods.
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/llmutil",
        "//pkg/test/testutil",
    ],
)
