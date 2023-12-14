load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "xdp_loader",
    srcs = [
        "main.go",
    ],
    pure = True,
    visibility = ["//:sandbox"],
    deps = [
        "//runsc/flag",
        "//tools/xdp/cmd",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
