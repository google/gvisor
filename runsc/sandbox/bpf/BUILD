load("//tools:defs.bzl", "bpf_program")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

bpf_program(
    name = "af_xdp_ebpf",
    src = "af_xdp.ebpf.c",
    hdrs = [],
    bpf_object = "af_xdp_ebpf.o",
    visibility = ["//:sandbox"],
)
