load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "checklinkname",
    srcs = ["check_linkname.go"],
    nogo = False,
    stateify = False,
    visibility = ["//tools/nogo:__subpackages__"],
    deps = ["@org_golang_x_tools//go/analysis:go_default_library"],
)
