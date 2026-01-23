load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "hostlayoutgen",
    srcs = [
        "hostlayoutgen.go",
        "hostlayoutgen_template.go",
    ],
    visibility = ["//visibility:public"],
)
