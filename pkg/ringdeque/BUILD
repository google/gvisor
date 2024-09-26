load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "ringdeque",
    srcs = [
        "ringdeque.go",
    ],
    stateify = False,
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "ringdeque_test",
    size = "small",
    srcs = ["ringdeque_test.go"],
    library = ":ringdeque",
)
