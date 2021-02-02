load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "github",
    srcs = ["main.go"],
    nogo = False,
    deps = [
        "//tools/github/nogo",
        "//tools/github/reviver",
        "@com_github_google_go_github_v32//github:go_default_library",
        "@org_golang_x_oauth2//:go_default_library",
    ],
)
