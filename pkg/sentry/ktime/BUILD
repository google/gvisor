load("//tools:defs.bzl", "go_library", "go_test")
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

go_template_instance(
    name = "synthetic_timer_list",
    out = "synthetic_timer_list.go",
    package = "ktime",
    prefix = "syntheticTimer",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*SyntheticTimer",
        "Linker": "*SyntheticTimer",
    },
)

go_template_instance(
    name = "synthetic_timer_set",
    out = "synthetic_timer_set.go",
    package = "ktime",
    prefix = "syntheticTimer",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "uint64Range",
        "Value": "syntheticTimerQueue",
        "Functions": "syntheticTimerSetFunctions",
    },
)

go_template_instance(
    name = "uint64_range",
    out = "uint64_range.go",
    package = "ktime",
    prefix = "uint64",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uint64",
    },
)

go_library(
    name = "ktime",
    srcs = [
        "context.go",
        "ktime.go",
        "sampled_timer.go",
        "seqatomic_sampled_clock_unsafe.go",
        "synthetic_timer.go",
        "synthetic_timer_list.go",
        "synthetic_timer_set.go",
        "uint64_range.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/gohacks",
        "//pkg/sync",
        "//pkg/waiter",
    ],
)

go_test(
    name = "ktime_test",
    size = "small",
    srcs = [
        "synthetic_timer_test.go",
    ],
    library = ":ktime",
)
