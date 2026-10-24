load("//tools:defs.bzl", "go_binary")

package(default_applicable_licenses = ["//:license"])

filegroup(
    name = "go_export_sources",
    srcs = glob(
        ["*.go"],
        exclude = ["*_test.go"],
    ),
    visibility = ["//:__pkg__"],
)

go_binary(
    name = "checklocks",
    srcs = ["main.go"],
    deps = [
        "//tools/checklocks",
        "@org_golang_x_tools//go/analysis/singlechecker:go_default_library",
    ],
)
