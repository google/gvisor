load("//tools:defs.bzl", "expand_template", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# Preserve whitespace that gofmt would otherwise remove from the directives.
expand_template(
    name = "nosplit_source",
    out = "nosplit.go",
    substitutions = {
        "{CR}": "\r",
        "{NBSP}": " ",
        "{SPACE}": " ",
        "{TAB}": "\t",
    },
    template = "nosplit.go.in",
)

go_library(
    name = "test1",
    srcs = [
        "test1.go",
        "test1_unsafe.go",
        ":nosplit_source",
    ],
    stateify = False,
    visibility = ["//tools/checkescape/test2:__pkg__"],
)
