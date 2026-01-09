load("//pkg/sync/locking:locking.bzl", "declare_mutex")
load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

declare_mutex(
    name = "abstract_socket_namespace_mutex",
    out = "abstract_socket_namespace_mutex.go",
    package = "inet",
    prefix = "abstractSocketNamespace",
)

declare_mutex(
    name = "nlmcast_table_mutex",
    out = "nlmcast_table_mutex.go",
    package = "inet",
    prefix = "nlmcastTable",
)

go_library(
    name = "inet",
    srcs = [
        "abstract_socket_namespace.go",
        "abstract_socket_namespace_mutex.go",
        "context.go",
        "inet.go",
        "namespace.go",
        "nlmcast.go",
        "nlmcast_table_mutex.go",
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
