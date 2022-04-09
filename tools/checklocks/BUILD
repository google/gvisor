load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "checklocks",
    srcs = [
        "analysis.go",
        "annotations.go",
        "checklocks.go",
        "facts.go",
        "state.go",
    ],
    nogo = False,
    visibility = [
        "//:__pkg__",
        "//tools/checklocks/cmd:__subpackages__",
        "//tools/nogo:__subpackages__",
    ],
    deps = [
        "//pkg/atomicbitops",
        "@org_golang_x_tools//go/analysis:go_default_library",
        "@org_golang_x_tools//go/analysis/passes/buildssa:go_default_library",
        "@org_golang_x_tools//go/ssa:go_default_library",
    ],
)
