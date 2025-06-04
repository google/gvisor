# Filesystem

[TOC]

gVisor accesses the filesystem through a file proxy, called the Gofer. The gofer
runs as a separate process, that is isolated from the sandbox. Gofer instances
communicate with their respective sentry using the LISAFS protocol.

Configuring the filesystem provides performance benefits, but isn't the only
step to optimizing gVisor performance. See the [Production guide] for more.

## Sandbox overlay

To isolate the host filesystem from the sandbox, you can set a writable tmpfs
overlay on top of the entire filesystem. All modifications are made to the
overlay, keeping the host filesystem unmodified.

> **Note**: All created and modified files are stored in memory inside the
> sandbox.

To use the tmpfs overlay, add the following `runtimeArgs` to your Docker
configuration (`/etc/docker/daemon.json`) and restart the Docker daemon:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--overlay2=all:memory"
            ]
       }
    }
}
```

### Root Filesystem Overlay

Any modifications to the root filesystem is destroyed with the container. So it
almost always makes sense to apply an overlay on top of the root filesystem.
This can drastically boost performance, as runsc will handle root filesystem
changes completely in memory instead of making costly round trips to the gofer
and make syscalls to modify the host.

However, holding so much file data in memory for the root filesystem can bloat
up container memory usage. To circumvent this, you can have root mount's upper
layer (tmpfs) be backed by a host file, so all file data is stored on disk.

The newer `--overlay2` flag allows you to achieve these. You can specify
`--overlay2=root:self` in `runtimeArgs`. The overlay backing host file will be
created in the container's root filesystem. This file will be hidden from the
containerized application. Placing the host file in the container's root
filesystem is important because k8s scans the container's root filesystem from
the host to enforce local ephemeral storage limits. You can also place the
overlay host file in another directory using `--overlay2=root:/path/dir`.

Self-backed rootfs overlay (`--overlay2=root:self`) is enabled by default in
runsc for performance. If you need to propagate rootfs changes to the host
filesystem, then disable it with `--overlay2=none`.

Overlay has `size=` option which is passed as `size=` tmpfs mount option. For
example, `--overlay2=root:memory,size=2g`.

## Directfs

Directfs is a feature that allows the sandbox process to directly access the
container filesystem. Directfs is enabled by default in runsc and can be
disabled with `--directfs=false` flag. Directfs provides reasonable security
while maintaining good performance by avoiding gofer round trips. Irrespective
of this setting, the container filesystem is always owned by the gofer process
and the sandbox mount namespace is always empty. To learn more, see our
[blog post](https://gvisor.dev/blog/2023/06/27/directfs/) about it.

When directfs is enabled, the gofer process donates file descriptors for all
mount points to the sandbox. The sandbox then uses file descriptor based system
calls (like `openat(2)`, `fchownat(2)`, etc) to access and operate on files
directly. The sandbox can only operate on filesystem trees exposed to it by the
gofer and cannot access the host's filesystem. There are additional security
measures like enforcing the usage of `O_NOFOLLOW` via seccomp and ensuring that
host filesystem FDs are not leaked on sandbox startup.

When directfs is disabled, the sandbox runs with stricter seccomp filters and
fewer capabilities such that the sandbox process can not perform filesystem
operations. It communicates with the Gofer process (via RPCs) to perform
filesystem operations on its behalf. This increases security but comes with a
performance trade-off.

## Shared root filesystem

The root filesystem is where the image is extracted and is not generally
modified from outside the sandbox. This allows for some optimizations, like
skipping checks to determine if a directory has changed since the last time it
was cached, thus missing updates that may have happened. If you need to `docker
cp` files inside the root filesystem, you may want to enable shared mode. Just
be aware that file system access will be slower due to the extra checks that are
required.

> Note: External mounts are always shared.

To use set the root filesystem shared, add the following `runtimeArgs` to your
Docker configuration (`/etc/docker/daemon.json`) and restart the Docker daemon:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--file-access=shared"
            ]
       }
    }
}
```

[Production guide]: ../production/
