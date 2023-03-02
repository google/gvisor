load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "hostcpu",
    srcs = [
        "getcpu_amd64.s",
        "getcpu_arm64.s",
        "hostcpu.go",
    ],
    visibility = ["//:sandbox"],
)

go_test(
    name = "hostcpu_test",
    size = "small",
    srcs = ["hostcpu_test.go"],
    library = ":hostcpu",
)
