load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "server",
    srcs = ["main.go"],
    pure = True,
    visibility = ["//website:__pkg__"],
    deps = [
        "@com_github_google_pprof//driver:go_default_library",
    ],
)
