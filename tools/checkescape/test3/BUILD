load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "test3",
    srcs = [
        "main.go",
        "tagged.go",
    ],
    gotags = ["checkescape_binary"],
    pure = True,
    testonly = True,
)
