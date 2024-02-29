load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "ollama",
    testonly = 1,
    srcs = ["ollama.go"],
    stateify = False,  # Does not support some generics methods.
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)
