load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_test(
    name = "parsers_test",
    size = "small",
    srcs = ["go_parser_test.go"],
    library = ":parsers",
    nogo = False,
    deps = [
        "//tools/bigquery",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

go_library(
    name = "parsers",
    testonly = 1,
    srcs = [
        "go_parser.go",
    ],
    nogo = False,
    visibility = ["//:sandbox"],
    deps = [
        "//test/benchmarks/tools",
        "//tools/bigquery",
    ],
)
