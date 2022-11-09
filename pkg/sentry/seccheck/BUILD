load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "seqatomic_sinkslice",
    out = "seqatomic_sinkslice_unsafe.go",
    package = "seccheck",
    suffix = "SinkSlice",
    template = "//pkg/sync/seqatomic:generic_seqatomic",
    types = {
        "Value": "[]Sink",
    },
)

go_library(
    name = "seccheck",
    srcs = [
        "config.go",
        "metadata.go",
        "metadata_amd64.go",
        "metadata_arm64.go",
        "seccheck.go",
        "seqatomic_sinkslice_unsafe.go",
        "syscall.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/fd",
        "//pkg/gohacks",
        "//pkg/log",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sync",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)

go_test(
    name = "seccheck_test",
    size = "small",
    srcs = [
        "config_test.go",
        "metadata_test.go",
        "seccheck_test.go",
    ],
    library = ":seccheck",
    deps = [
        "//pkg/context",
        "//pkg/fd",
        "//pkg/sentry/seccheck/points:points_go_proto",
    ],
)
