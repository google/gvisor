# FAQ

[TOC]

### What operating systems are supported? {#supported-os}

Today, gVisor requires Linux.

### What CPU architectures are supported? {#supported-cpus}

gVisor currently supports [x86_64/AMD64](https://en.wikipedia.org/wiki/X86-64)
compatible processors. Preliminary support is also available for
[ARM64](https://en.wikipedia.org/wiki/ARM_architecture#AArch64).

### Do I need to modify my Linux application to use gVisor? {#modify-app}

No. gVisor is capable of running unmodified Linux binaries.

### What binary formats does gVisor support? {#supported-binaries}

gVisor supports Linux
[ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) binaries.

Binaries run in gVisor should be built for the
[AMD64](https://en.wikipedia.org/wiki/X86-64) or
[AArch64](https://en.wikipedia.org/wiki/ARM_architecture#AArch64) CPU
architectures.

### Can I run Docker images using gVisor? {#docker-images}

Yes. Please see the [Docker Quick Start][docker].

### Can I run Kubernetes pods using gVisor? {#k8s-pods}

Yes. Please see the [Kubernetes Quick Start][k8s].

### What's the security model? {#security-model}

See the [Security Model][security-model].

## Troubleshooting

### My container runs fine with `runc` but fails with `runsc` {#app-compatibility}

If you’re having problems running a container with `runsc` it’s most likely due
to a compatibility issue or a missing feature in gVisor. See
[Debugging][debugging].

### When I run my container, docker fails with: `open /run/containerd/.../<containerid>/log.json: no such file or directory` {#memfd-create}

You are using an older version of Linux which doesn't support `memfd_create`.

This is tracked in [bug #268](https://gvisor.dev/issue/268).

### When I run my container, docker fails with: `flag provided but not defined: -console` {#old-docker}

You're using an old version of Docker. See [Docker Quick Start][docker].

### I can’t see a file copied with: `docker cp` {#fs-cache}

For performance reasons, gVisor caches directory contents, and therefore it may
not realize a new file was copied to a given directory. To invalidate the cache
and force a refresh, create a file under the directory in question and list the
contents again.

As a workaround, shared root filesystem can be enabled. See
[Filesystem][filesystem].

This bug is tracked in [bug #4](https://gvisor.dev/issue/4).

Note that `kubectl cp` works because it does the copy by exec'ing inside the
sandbox, and thus gVisor's internal cache is made aware of the new files and
directories.

### I'm getting an error like: `panic: unable to attach: operation not permitted` or `fork/exec /proc/self/exe: invalid argument: unknown` {#runsc-perms}

Make sure that permissions and the owner is correct on the `runsc` binary.

```bash
sudo chown root:root /usr/local/bin/runsc
sudo chmod 0755 /usr/local/bin/runsc
```

### I'm getting an error like `mount submount "/etc/hostname": creating mount with source ".../hostname": input/output error: unknown.` {#memlock}

There is a bug in Linux kernel versions 5.1 to 5.3.15, 5.4.2, and 5.5. Upgrade
to a newer kernel or add the following to
`/lib/systemd/system/containerd.service` as a workaround.

```
LimitMEMLOCK=infinity
```

And run `systemctl daemon-reload && systemctl restart containerd` to restart
containerd.

See [issue #1765](https://gvisor.dev/issue/1765) for more details.

### My container cannot resolve another container's name when using Docker user defined bridge {#docker-bridge}

This is normally indicated by errors like `bad address 'container-name'` when
trying to communicate to another container in the same network.

Docker user defined bridge uses an embedded DNS server bound to the loopback
interface on address 127.0.0.10. This requires access to the host network in
order to communicate to the DNS server. runsc network is isolated from the host
and cannot access the DNS server on the host network without breaking the
sandbox isolation. There are a few different workarounds you can try:

*   Use default bridge network with `--link` to connect containers. Default
    bridge doesn't use embedded DNS.
*   Use [`--network=host`][host-net] option in runsc, however beware that it
    will use the host network stack and is less secure.
*   Use IPs instead of container names.
*   Use [Kubernetes][k8s]. Container name lookup works fine in Kubernetes.

[security-model]: /docs/architecture_guide/security/
[host-net]: /docs/user_guide/networking/#network-passthrough
[debugging]: /docs/user_guide/debugging/
[filesystem]: /docs/user_guide/filesystem/
[docker]: /docs/user_guide/quick_start/docker/
[k8s]: /docs/user_guide/quick_start/kubernetes/
