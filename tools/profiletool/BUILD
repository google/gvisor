load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "profiletool",
    srcs = ["profiletool.go"],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/log",
        "//runsc/flag",
        "@com_github_google_pprof//profile:go_default_library",
    ],
)
