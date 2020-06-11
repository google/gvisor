load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "merkletree",
    srcs = ["merkletree.go"],
    deps = ["//pkg/usermem"],
)

go_test(
    name = "merkletree_test",
    srcs = ["merkletree_test.go"],
    library = ":merkletree",
    deps = ["//pkg/usermem"],
)
