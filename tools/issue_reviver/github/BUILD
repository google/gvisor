load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "github",
    srcs = ["github.go"],
    nogo = False,
    visibility = [
        "//tools/issue_reviver:__subpackages__",
    ],
    deps = [
        "//tools/issue_reviver/reviver",
        "@com_github_google_go_github_v28//github:go_default_library",
        "@org_golang_x_oauth2//:go_default_library",
    ],
)
