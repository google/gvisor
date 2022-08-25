load("//tools:defs.bzl", "bpf_program")

package(licenses = ["notice"])

bpf_program(
    name = "pass_ebpf",
    src = "pass.ebpf.c",
    hdrs = [],
    bpf_object = "pass_ebpf.o",
    visibility = ["//:sandbox"],
)

bpf_program(
    name = "drop_ebpf",
    src = "drop.ebpf.c",
    hdrs = [],
    bpf_object = "drop_ebpf.o",
    visibility = ["//:sandbox"],
)

bpf_program(
    name = "tcpdump_ebpf",
    src = "tcpdump.ebpf.c",
    hdrs = [],
    bpf_object = "tcpdump_ebpf.o",
    visibility = ["//:sandbox"],
)
