load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "xdp_loader",
    srcs = [
        "drop.go",
        "main.go",
        "pass.go",
        "tcpdump.go",
    ],
    embedsrcs = [
        "//tools/xdp/bpf:drop_ebpf.o",  # keep
        "//tools/xdp/bpf:pass_ebpf.o",  # keep
        "//tools/xdp/bpf:tcpdump_ebpf.o",  # keep
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/bufferv2",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/stack",
        "//pkg/xdp",
        "//runsc/flag",
        "@com_github_cilium_ebpf//:go_default_library",
        "@com_github_cilium_ebpf//link:go_default_library",
        "@com_github_google_subcommands//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
