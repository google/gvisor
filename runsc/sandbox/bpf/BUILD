load("//tools:defs.bzl", "bpf_program", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "bpf",
    srcs = ["bpf.go"],
    embedsrcs = [
        "af_xdp_ebpf.o",  # keep
        "tunnel_veth_ebpf.o",  # keep
    ],
    visibility = ["//visibility:public"],
)

bpf_program(
    name = "af_xdp_ebpf",
    src = "af_xdp.ebpf.c",
    hdrs = [],
    bpf_object = "af_xdp_ebpf.o",
    visibility = ["//:sandbox"],
)

bpf_program(
    name = "tunnel_veth_ebpf",
    src = "tunnel_veth.ebpf.c",
    hdrs = [],
    bpf_object = "tunnel_veth_ebpf.o",
    visibility = ["//:sandbox"],
)
