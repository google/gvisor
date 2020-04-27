load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "issue_reviver",
    srcs = ["main.go"],
    deps = [
        "//tools/issue_reviver/github",
        "//tools/issue_reviver/reviver",
    ],
)
