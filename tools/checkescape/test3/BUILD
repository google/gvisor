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
    ],
    gotags = ["checkescape_binary"],
    pure = True,
)

go_binary(
    name = "test3-race",
    testonly = True,
    srcs = [
        "main.go",
        "tagged.go",
    ],
    gotags = ["checkescape_binary"],
    race = "on",
)
