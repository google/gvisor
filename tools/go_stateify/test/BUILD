load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "test",
    testonly = True,
    srcs = ["transparent.go"],
    deps = [
        "//pkg/state",
        "//tools/go_stateify/test/external",
    ],
)

go_test(
    name = "transparent_test",
    size = "small",
    srcs = ["transparent_test.go"],
    library = ":test",
    deps = [
        "//pkg/state",
        "//tools/go_stateify/test/external",
    ],
)
