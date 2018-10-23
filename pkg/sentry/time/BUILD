load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_generics:defs.bzl", "go_template_instance")

go_template_instance(
    name = "seqatomic_parameters",
    out = "seqatomic_parameters.go",
    package = "time",
    suffix = "Parameters",
    template = "//pkg/sync:generic_seqatomic",
    types = {
        "Value": "Parameters",
    },
)

go_library(
    name = "time",
    srcs = [
        "calibrated_clock.go",
        "clock_id.go",
        "clocks.go",
        "muldiv_amd64.s",
        "parameters.go",
        "sampler.go",
        "sampler_unsafe.go",
        "seqatomic_parameters.go",
        "tsc_amd64.s",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/time",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/log",
        "//pkg/metric",
        "//pkg/sync",
        "//pkg/syserror",
    ],
)

go_test(
    name = "time_test",
    srcs = [
        "calibrated_clock_test.go",
        "parameters_test.go",
        "sampler_test.go",
    ],
    embed = [":time"],
)
