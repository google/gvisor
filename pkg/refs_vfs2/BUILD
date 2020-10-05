load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template")

package(licenses = ["notice"])

go_template(
    name = "refs_template",
    srcs = [
        "refs_template.go",
    ],
    types = [
        "T",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/refs",
    ],
)

go_library(
    name = "refs_vfs2",
    srcs = ["refs.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/context"],
)
