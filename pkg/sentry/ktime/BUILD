load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_template_instance(
    name = "seqatomic_clock",
    out = "seqatomic_clock_unsafe.go",
    package = "ktime",
    suffix = "Clock",
    template = "//pkg/sync/seqatomic:generic_seqatomic",
    types = {
        "Value": "Clock",
    },
)

go_library(
    name = "ktime",
    srcs = [
        "context.go",
        "ktime.go",
        "seqatomic_clock_unsafe.go",
        "util.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/gohacks",
        "//pkg/sync",
        "//pkg/waiter",
    ],
)
