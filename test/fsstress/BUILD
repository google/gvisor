load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_test(
    name = "fsstress_test",
    size = "large",
    srcs = [
        "fsstress_test.go",
    ],
    library = ":fsstress",
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        "manual",
        "local",
    ],
    deps = [
        "//pkg/test/dockerutil",
    ],
)

go_library(
    name = "fsstress",
    srcs = ["fsstress.go"],
)
