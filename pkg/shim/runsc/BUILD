load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "runsc",
    srcs = [
        "runsc.go",
        "utils.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "@com_github_containerd_go_runc//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
