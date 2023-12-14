load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "xdp_loader",
    srcs = [
        "drop.go",
        "main.go",
        "pass.go",
        "redirect_host.go",
        "tcpdump.go",
    ],
    embedsrcs = [
        "//tools/xdp/bpf:drop_ebpf.o",  # keep
        "//tools/xdp/bpf:pass_ebpf.o",  # keep
        "//tools/xdp/bpf:redirect_host_ebpf.o",  # keep
        "//tools/xdp/bpf:tcpdump_ebpf.o",  # keep
    ],
    pure = True,
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
