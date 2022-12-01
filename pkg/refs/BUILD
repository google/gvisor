load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template")

package(licenses = ["notice"])

go_template(
    name = "refs_template",
    srcs = [
        "refs_template.go",
    ],
    opt_consts = [
        "enableLogging",
    ],
    types = [
        "T",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/refs",
    ],
)

go_library(
    name = "refs",
    srcs = [
        "refcounter.go",
        "refs_map.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/log",
        "//pkg/sync",
    ],
)
