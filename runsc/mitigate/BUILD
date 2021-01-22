load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "mitigate",
    srcs = [
        "cpu.go",
        "mitigate.go",
    ],
)

go_test(
    name = "mitigate_test",
    size = "small",
    srcs = ["cpu_test.go"],
    library = ":mitigate",
)
