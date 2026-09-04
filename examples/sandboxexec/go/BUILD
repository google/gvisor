load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "doc_processor",
    srcs = ["doc_processor.go"],
    deps = [
        "//sandboxexec/sandbox",
    ],
)
