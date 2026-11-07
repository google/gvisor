load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "gccontrol",
    srcs = ["gccontrol.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sync",
    ],
)

go_test(
    name = "gccontrol_test",
    size = "small",
    srcs = ["gccontrol_test.go"],
    library = ":gccontrol",
)
