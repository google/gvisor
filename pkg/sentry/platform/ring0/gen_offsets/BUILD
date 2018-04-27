package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_binary")
load("//tools/go_generics:defs.bzl", "go_template_instance")

go_template_instance(
    name = "defs_impl",
    out = "defs_impl.go",
    package = "main",
    template = "//pkg/sentry/platform/ring0:defs",
)

go_binary(
    name = "gen_offsets",
    srcs = [
        "defs_impl.go",
        "main.go",
    ],
    visibility = ["//pkg/sentry/platform/ring0:__pkg__"],
    deps = [
        "//pkg/cpuid",
        "//pkg/sentry/platform/ring0/pagetables",
        "//pkg/sentry/usermem",
    ],
)
