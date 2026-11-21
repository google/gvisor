load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "gohacks",
    srcs = [
        "linkname_go113_unsafe.go",
        "noescape_unsafe.go",
        "string_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/gohacks",
    stateify = False,
    visibility = ["//:sandbox"],
)

go_test(
    name = "gohacks_test",
    size = "small",
    srcs = [
        "gohacks_test.go",
        "string_test.go",
    ],
    embed = [":gohacks"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
