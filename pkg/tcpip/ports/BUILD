load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "port_manager_mutex",
    out = "port_manager_mutex.go",
    package = "ports",
    prefix = "portManager",
    substrs = {
        "genericMark": "portManager",
    },
    template = "//pkg/sync/locking:generic_rwmutex",
)

go_template_instance(
    name = "ephemeral_mutex",
    out = "ephemeral_mutex.go",
    package = "ports",
    prefix = "ephemeral",
    substrs = {
        "genericMark": "ephemeral",
    },
    template = "//pkg/sync/locking:generic_rwmutex",
)

go_library(
    name = "ports",
    srcs = [
        "ephemeral_mutex.go",
        "flags.go",
        "port_manager_mutex.go",
        "ports.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
    ],
)

go_test(
    name = "ports_test",
    srcs = ["ports_test.go"],
    library = ":ports",
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/testutil",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
