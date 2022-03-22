load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "seqatomic_checkerslice",
    out = "seqatomic_checkerslice_unsafe.go",
    package = "seccheck",
    suffix = "CheckerSlice",
    template = "//pkg/sync/seqatomic:generic_seqatomic",
    types = {
        "Value": "[]Checker",
    },
)

go_library(
    name = "seccheck",
    srcs = [
        "clone.go",
        "config.go",
        "execve.go",
        "exit.go",
        "metadata.go",
        "metadata_amd64.go",
        "seccheck.go",
        "seccheck_amd64.go",
        "seccheck_arm64.go",
        "seqatomic_checkerslice_unsafe.go",
        "syscall.go",
        "task.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
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
    srcs = ["seccheck_test.go"],
    library = ":seccheck",
    deps = [
        "//pkg/context",
        "//pkg/sentry/seccheck/points:points_go_proto",
    ],
)
