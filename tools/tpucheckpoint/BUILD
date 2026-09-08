load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "tpucheckpoint",
    srcs = ["tpucheckpoint.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//tools/tpucheckpoint/tpucontrol",
    ],
)
