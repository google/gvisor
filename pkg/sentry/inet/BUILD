load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
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
        "test_stack.go",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)
