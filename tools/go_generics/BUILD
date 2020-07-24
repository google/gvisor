load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "go_generics",
    srcs = [
        "generics.go",
        "imports.go",
        "remove.go",
    ],
    visibility = ["//:sandbox"],
    deps = ["//tools/go_generics/globals"],
)
