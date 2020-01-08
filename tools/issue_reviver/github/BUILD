load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "github",
    srcs = ["github.go"],
    importpath = "gvisor.dev/gvisor/tools/issue_reviver/github",
    visibility = [
        "//tools/issue_reviver:__subpackages__",
    ],
    deps = [
        "//tools/issue_reviver/reviver",
        "@com_github_google_go-github//github:go_default_library",
        "@org_golang_x_oauth2//:go_default_library",
    ],
)
