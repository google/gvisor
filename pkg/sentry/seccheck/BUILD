load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

licenses(["notice"])

go_template(
    name = "generic_field_set",
    srcs = ["generic_field_set.go"],
    opt_consts = [
        "numFieldSetWords",
    ],
    visibility = ["//visibility:private"],
)

go_template_instance(
    name = "clone_field_set",
    out = "clone_field_set.go",
    package = "seccheck",
    prefix = "Clone",
    template = ":generic_field_set",
)

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
        "clone_field_set.go",
        "seccheck.go",
        "seqatomic_checkerslice_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/gohacks",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sync",
    ],
)
