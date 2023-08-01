load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_template_instance(
    name = "namespace_refs",
    out = "namespace_refs.go",
    package = "inet",
    prefix = "namespace",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "Namespace",
    },
)

go_library(
    name = "inet",
    srcs = [
        "context.go",
        "inet.go",
        "namespace.go",
        "namespace_refs.go",
        "test_stack.go",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/refs",
        "//pkg/sentry/fsimpl/nsfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)
