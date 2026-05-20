load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "vllm",
    testonly = True,
    srcs = [
        "vllm.go",
    ],
    stateify = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/llmutil",
        "//pkg/test/testutil",
    ],
)
