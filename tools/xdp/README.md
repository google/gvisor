# XDP

This directory contains tools for using XDP and, importantly, provides examples.

The `xdp_loader` program can attach one of three programs to a network device.
Those programs, specified via the `-program` flag, can be:

-   `pass` - Allow all traffic, passing it on to the kernel network stack.
-   `drop` - Drop all traffic before it hits the kernel network stack.
-   `tcpdump` - Use an `AF_XDP` socket to print all network traffic. Unlike the
    normal `tcpdump` tool, intercepted packets are not also passed to the kernel
    network stack.

# How do the examples work?

## `XDP`

The XDP pass and drop programs simply allow or drop all traffic on a given NIC.
These examples give an idea of how to use the Cilium eBPF library and how to
build eBPF programs within gVisor.

## `AF_XDP`

The code supporting `tcpdump` is a minimal example of using an `AF_XDP` socket
to receive packets. There are very few other examples of `AF_XDP` floating
around the internet. They all use the in-tree libbpf library
unfortunately.[^libxdp]

The XDP project has a useful [example][af_xdp_tutorial] that uses libbpf. One
must also look at [libbpf itself][libbpf] to understand what's really going on.

## TODO

-   Kernel version < 5.4 has some weird offsets behavior. Just don't run on
    those machines.
-   Implement SHARED, although it looks like we usually run with only 1
    dispatcher.
-   Add a -redirect $fromdev $todev option in order to test fast path.

[af_xdp_tutorial]: https://github.com/xdp-project/xdp-tutorial/tree/master/advanced03-AF_XDP
[libbpf]: https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf/xsk.c
[^libxdp]: XDP functionality has since moved to libxdp, but nobody seems to be
    using it yet.
