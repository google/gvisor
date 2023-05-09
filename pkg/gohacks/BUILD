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
        "slice_go113_unsafe.go",
        "slice_go120_unsafe.go",
        "string_go113_unsafe.go",
        "string_go120_unsafe.go",
    ],
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
    library = ":gohacks",
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
