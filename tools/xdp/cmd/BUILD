load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "cmd",
    srcs = [
        "cmd.go",
        "drop.go",
        "pass.go",
        "redirect_host.go",
        "tcpdump.go",
        "tunnel.go",
    ],
    embedsrcs = [
        "//tools/xdp/cmd/bpf:drop_ebpf.o",  # keep
        "//tools/xdp/cmd/bpf:pass_ebpf.o",  # keep
        "//tools/xdp/cmd/bpf:redirect_host_ebpf.o",  # keep
        "//tools/xdp/cmd/bpf:tcpdump_ebpf.o",  # keep
        "//tools/xdp/cmd/bpf:tunnel_host_ebpf.o",  # keep
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/buffer",
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
