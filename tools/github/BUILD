load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "github",
    srcs = ["main.go"],
    nogo = False,
    deps = [
        "//tools/github/reviver",
        "@com_github_google_go_github_v42//github:go_default_library",
        "@org_golang_x_oauth2//:go_default_library",
    ],
)
