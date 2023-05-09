load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "go_merge",
    srcs = ["main.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//tools/constraintutil",
    ],
)
