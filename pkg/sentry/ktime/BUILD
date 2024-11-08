load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_template_instance(
    name = "seqatomic_sampled_clock",
    out = "seqatomic_sampled_clock_unsafe.go",
    package = "ktime",
    suffix = "SampledClock",
    template = "//pkg/sync/seqatomic:generic_seqatomic",
    types = {
        "Value": "SampledClock",
    },
)

go_library(
    name = "ktime",
    srcs = [
        "context.go",
        "ktime.go",
        "sampled_timer.go",
        "seqatomic_sampled_clock_unsafe.go",
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
