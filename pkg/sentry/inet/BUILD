load("//pkg/sync/locking:locking.bzl", "declare_mutex")
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

declare_mutex(
    name = "abstract_socket_namespace_mutex",
    out = "abstract_socket_namespace_mutex.go",
    package = "inet",
    prefix = "abstractSocketNamespace",
)

go_library(
    name = "inet",
    srcs = [
        "abstract_socket_namespace.go",
        "abstract_socket_namespace_mutex.go",
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
        "//pkg/sentry/socket/netlink/nlmsg",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)
