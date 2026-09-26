load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "test3",
    testonly = True,
    srcs = [
        "main.go",
        "tagged.go",
        "untagged.go",
    ],
    gotags = ["checkescape_binary"],
    pure = True,
)
