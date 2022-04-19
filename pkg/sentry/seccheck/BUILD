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
        "execve.go",
        "exit.go",
        "seccheck.go",
        "seqatomic_checkerslice_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/gohacks",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sync",
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
