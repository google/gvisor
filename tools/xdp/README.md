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

TODO for XDP\_REDIRECT:

-   Install a map of index (always 0 at first) to device on the host nic
-   Redirect everything but port 22 to that device (reuse other ebpf program)
-   When runsc runs, have it install the host-facing veth as the value in the
    map
-   Also use an XDP socket inside gVisor
-   Shouldn't require any new flags. Just do it in the xdp\_loader
-   We actually need 3 programs:
    -   One on the host nic to redirect to the host-facing end of the veth
    -   Do this via xdp\_loader
    -   One on the host-facing end of the veth to redirect out the host nic
    -   Do this via xdp\_loader
    -   One on the sentry-facing end of the veth to read packets from
    -   This is done. It's just the regular xdp endpoint.

STATUS: It builds, it runs... and there's not connectivity.

-   Are the programs attached?
-   What are we doing address-wise?
    -   In GKE, we actually want to use the address of the pod.
    -   Elsewhere (i.e. anywhere we'd use docker's `-p` flag), we want to use
        the address of the host.
    -   Right now, we're doing the GKE thing.
    -   Wow, there are way to many XDP modes atm. We'll have to remove some when
        stable.
    -   I can just reuse prepareRedirectInterfaceArgs, but connect to the ns nic
        instead of the host one
