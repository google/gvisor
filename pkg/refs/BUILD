load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "refs",
    srcs = [
        "refcounter.go",
        "refs_map.go",
        "refs_template.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/log",
        "//pkg/sync",
    ],
)
