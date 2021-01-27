load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "mitigate",
    srcs = [
        "cpu.go",
        "mitigate.go",
    ],
    deps = ["@in_gopkg_yaml_v2//:go_default_library"],
)

go_test(
    name = "mitigate_test",
    size = "small",
    srcs = ["cpu_test.go"],
    library = ":mitigate",
    deps = ["@com_github_google_go_cmp//cmp:go_default_library"],
)
