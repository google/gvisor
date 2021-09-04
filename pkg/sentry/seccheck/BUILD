load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_fieldenum:defs.bzl", "go_fieldenum")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_fieldenum(
    name = "seccheck_fieldenum",
    srcs = [
        "clone.go",
        "task.go",
    ],
    out = "seccheck_fieldenum.go",
    package = "seccheck",
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
        "seccheck.go",
        "seccheck_fieldenum.go",
        "seqatomic_checkerslice_unsafe.go",
        "task.go",
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

go_test(
    name = "seccheck_test",
    size = "small",
    srcs = ["seccheck_test.go"],
    library = ":seccheck",
    deps = ["//pkg/context"],
)
