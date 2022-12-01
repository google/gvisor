load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
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

go_template_instance(
    name = "atomicptr_netns",
    out = "atomicptr_netns_unsafe.go",
    package = "inet",
    prefix = "Namespace",
    template = "//pkg/sync/atomicptr:generic_atomicptr",
    types = {
        "Value": "Namespace",
    },
)

go_library(
    name = "inet",
    srcs = [
        "atomicptr_netns_unsafe.go",
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
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)
