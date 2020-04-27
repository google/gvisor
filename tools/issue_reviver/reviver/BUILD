load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "reviver",
    srcs = ["reviver.go"],
    visibility = [
        "//tools/issue_reviver:__subpackages__",
    ],
)

go_test(
    name = "reviver_test",
    size = "small",
    srcs = ["reviver_test.go"],
    library = ":reviver",
)
