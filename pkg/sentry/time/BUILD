load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "seqatomic_parameters",
    out = "seqatomic_parameters_unsafe.go",
    package = "time",
    suffix = "Parameters",
    template = "//pkg/sync/seqatomic:generic_seqatomic",
    types = {
        "Value": "Parameters",
    },
)

go_library(
    name = "time",
    srcs = [
        "arith_arm64.go",
        "calibrated_clock.go",
        "clock_id.go",
        "clocks.go",
        "muldiv_amd64.s",
        "muldiv_arm64.s",
        "parameters.go",
        "sampler.go",
        "sampler_amd64.go",
        "sampler_arm64.go",
        "seqatomic_parameters_unsafe.go",
        "tsc_amd64.s",
        "tsc_arm64.s",
        "vdso.go",
        "vdso_amd64.s",
        "vdso_arm64.s",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/errors/linuxerr",
        "//pkg/gohacks",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "time_test",
    srcs = [
        "calibrated_clock_test.go",
        "parameters_test.go",
        "sampler_test.go",
        "vdso_test.go",
    ],
    library = ":time",
    deps = [
        "//pkg/abi/linux",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
