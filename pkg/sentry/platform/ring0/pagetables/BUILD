load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

package(licenses = ["notice"])

config_setting(
    name = "aarch64",
    constraint_values = ["@bazel_tools//platforms:aarch64"],
)

go_template(
    name = "generic_walker",
    srcs = select({
           ":aarch64": ["walker_arm64.go",],
           "//conditions:default": ["walker_amd64.go",],
    }),
    opt_types = [
        "Visitor",
    ],
    visibility = [":__pkg__"],
)

go_template_instance(
    name = "walker_map",
    out = "walker_map.go",
    package = "pagetables",
    prefix = "map",
    template = ":generic_walker",
    types = {
        "Visitor": "mapVisitor",
    },
)

go_template_instance(
    name = "walker_unmap",
    out = "walker_unmap.go",
    package = "pagetables",
    prefix = "unmap",
    template = ":generic_walker",
    types = {
        "Visitor": "unmapVisitor",
    },
)

go_template_instance(
    name = "walker_lookup",
    out = "walker_lookup.go",
    package = "pagetables",
    prefix = "lookup",
    template = ":generic_walker",
    types = {
        "Visitor": "lookupVisitor",
    },
)

go_template_instance(
    name = "walker_empty",
    out = "walker_empty.go",
    package = "pagetables",
    prefix = "empty",
    template = ":generic_walker",
    types = {
        "Visitor": "emptyVisitor",
    },
)

go_template_instance(
    name = "walker_check",
    out = "walker_check.go",
    package = "pagetables",
    prefix = "check",
    template = ":generic_walker",
    types = {
        "Visitor": "checkVisitor",
    },
)

go_library(
    name = "pagetables",
    srcs = [
        "allocator.go",
        "allocator_unsafe.go",
        "pagetables.go",
        "pagetables_aarch64.go",
        "pagetables_amd64.go",
        "pagetables_arm64.go",
        "pagetables_x86.go",
        "pcids_x86.go",
        "walker_amd64.go",
        "walker_arm64.go",
        "walker_empty.go",
        "walker_lookup.go",
        "walker_map.go",
        "walker_unmap.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/platform/ring0/pagetables",
    visibility = [
        "//pkg/sentry/platform/kvm:__subpackages__",
        "//pkg/sentry/platform/ring0:__subpackages__",
    ],
    deps = ["//pkg/sentry/usermem"],
)

go_test(
    name = "pagetables_test",
    size = "small",
    srcs = [
        "pagetables_amd64_test.go",
        "pagetables_arm64_test.go",
        "pagetables_test.go",
        "walker_check.go",
    ],
    embed = [":pagetables"],
    deps = ["//pkg/sentry/usermem"],
)
