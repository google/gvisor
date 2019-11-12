load("@io_bazel_rules_go//go:def.bzl", "go_binary")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "defs_impl_arm64",
    out = "defs_impl_arm64.go",
    package = "main",
    template = "//pkg/sentry/platform/ring0:defs_arm64",
)

go_template_instance(
    name = "defs_impl_amd64",
    out = "defs_impl_amd64.go",
    package = "main",
    template = "//pkg/sentry/platform/ring0:defs_amd64",
)

go_binary(
    name = "gen_offsets",
    srcs = [
        "defs_impl_amd64.go",
        "defs_impl_arm64.go",
        "main.go",
    ],
    visibility = ["//pkg/sentry/platform/ring0:__pkg__"],
    deps = [
        "//pkg/cpuid",
        "//pkg/sentry/platform/ring0/pagetables",
        "//pkg/sentry/usermem",
    ],
)
