package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_template_instance(
    name = "waiter_list",
    out = "waiter_list.go",
    package = "futex",
    prefix = "waiter",
    template = "//pkg/ilist:generic_list",
    types = {
        "Linker": "*Waiter",
    },
)

go_stateify(
    name = "futex_state",
    srcs = [
        "futex.go",
        "waiter_list.go",
    ],
    out = "futex_state.go",
    package = "futex",
)

go_library(
    name = "futex",
    srcs = [
        "futex.go",
        "futex_state.go",
        "waiter_list.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/futex",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/state",
        "//pkg/syserror",
    ],
)

go_test(
    name = "futex_test",
    size = "small",
    srcs = ["futex_test.go"],
    embed = [":futex"],
)
