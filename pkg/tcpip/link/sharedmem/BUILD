package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "sharedmem",
    srcs = [
        "rx.go",
        "sharedmem.go",
        "sharedmem_unsafe.go",
        "tx.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/sharedmem",
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/rawfile",
        "//pkg/tcpip/link/sharedmem/queue",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "sharedmem_test",
    srcs = [
        "sharedmem_test.go",
    ],
    embed = [":sharedmem"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/sharedmem/pipe",
        "//pkg/tcpip/link/sharedmem/queue",
        "//pkg/tcpip/stack",
    ],
)
