load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "checklinkname",
    srcs = [
        "check_linkname.go",
        "known.go",
    ],
    nogo = False,
    visibility = ["//tools/nogo:__subpackages__"],
    deps = [
        "@org_golang_x_tools//go/analysis:go_default_library",
    ],
)
