# Filesystem

[TOC]

gVisor accesses the filesystem through a file proxy, called the Gofer. The gofer
runs as a separate process, that is isolated from the sandbox. Gofer instances
communicate with their respective sentry using the LISAFS protocol.

Configuring the filesystem provides performance benefits, but isn't the only
step to optimizing gVisor performance. See the [Production guide] for more.

## Filesystem Overlay

To isolate the host filesystem from the sandbox, or to make a read-only
filesystem (like EROFS) writable, you can set a writable tmpfs overlay on top of
mounts. All modifications are made to the overlay, keeping the underlying
filesystem unmodified.

### Backing Mediums

The overlay can be backed by different mediums to manage memory and disk usage:

*   **Memory** (`memory`): The overlay is backed by application memory. This can
    bloat up container memory usage as all file data is stored in memory.
*   **Self** (`self`): The overlay is backed by a file within the mount itself
    (hidden from the application). This is useful to store modifications on disk
    instead of memory.
    *   For the root filesystem, the file is created in the container's root
        (configured via `spec.Root.Path`). This allows Kubernetes to account for
        the overlay usage against the container's ephemeral storage limits.
*   **Directory** (`dir=/path`): The overlay is backed by a file in the
    specified absolute path on the host.

### Global Configuration

To configure the overlay globally for all containers, use the `--overlay2` flag
with the format `--overlay2={mount}:{medium}[,size={size}]`.

*   `mount`: Can be `root` (root filesystem only) or `all` (all mounts).
*   `medium`: One of the [backing mediums](#backing-mediums) (`memory`, `self`,
    `dir=...`).
*   `size`: (Optional) Limit the size of the tmpfs upper layer (e.g., `2g`).

Examples:

*   `--overlay2=root:self`: Overlay the root filesystem with a file-backed tmpfs
    stored in the root filesystem itself. This is the default.
*   `--overlay2=all:memory`: Overlay all mounts with memory-backed tmpfs.
*   `--overlay2=root:dir=/tmp/overlay`: Overlay the root filesystem with a
    file-backed tmpfs stored in `/tmp/overlay`.

> **Note**: `self` backed rootfs overlay is typically enabled by default in
> runsc for performance. If you need to propagate rootfs changes to the host
> filesystem, disable it with `--overlay2=none`.

To use the tmpfs overlay, update the `runtimeArgs` in your Docker configuration
(`/etc/docker/daemon.json`) and restart the Docker daemon:

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

To set the root filesystem shared, add the following `runtimeArgs` to your
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

## Exclusive bind mounts

By default, all bind mounts are served by the gofer in "shared" mode
(`--file-access-mounts=shared`). In this mode, the gofer continuously
revalidates its dentry tree against the host filesystem. This is necessary
because the sandbox cannot assume exclusive access to the bind mounts, as they
may be observed or mutated by other processes on the host.

If you are confident that **all** bind mounts are exclusive to the sandbox
(i.e., no external process will modify the files), you can set
`--file-access-mounts=exclusive`. This enables aggressive caching in the
sandbox, significantly improving performance by reducing revalidation overhead.

Good candidates for this setting include:

*   **Static Data**: Directories containing immutable files (e.g. ML models,
    datasets) that are not modified on the host.
*   **Dedicated Storage**: Directories created specifically for the container
    that are not accessed by any other host process.

Note that this setting applies to **all** bind mounts within the sandbox. It
does not apply to the root filesystem, which is configured via the
`--file-access` flag (see [Shared Root Filesystem](#shared-root-filesystem)).

To enable exclusive access for bind mounts, add the following `runtimeArgs` to
your Docker configuration (`/etc/docker/daemon.json`) and restart the Docker
daemon:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--file-access-mounts=exclusive"
            ]
       }
    }
}
```

> **Warning**: Enabling exclusive mode on mounts that are modified externally
> can lead to data corruption or undefined behavior, as the sandbox may work
> with stale data.

## Dentry Cache

The gofer client maintains a tree of dentries (directory entries) that mirrors
the filesystem tree to accelerate path resolution. The **dentry cache** is a
subset of this tree that holds dentries with zero references. These correspond
to unreferenced leaf nodes in the filesystem tree (since every dentry holds a
reference to its parent, the internal nodes always have a reference).

The cache is an LRU cache that retains these unused dentries to prevent them
from being destroyed immediately. If a future filesystem request accesses the
same path, we can reuse the existing dentry from the cache instead of recreating
it, which improves performance.

By default, every gofer mount has its own dentry cache with a size of 1000. This
can be configured in two ways:

-   **Global Flag**: Passing the `--dcache` flag to `runsc` creates a single,
    global dentry cache of the specified size that is shared across all gofer
    mounts. You can specify it in `runtimeArgs`:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--dcache=5000"
            ]
       }
    }
}
```

-   **Mount Option**: The `dcache` mount option can be used to set the cache
    size on a per-mount basis:

```json
    "mounts": [
        {
            "type": "bind",
            "source": "/host/path",
            "destination": "/container/path",
            "options": [
                "dcache=500"
            ]
        }
    ]
```

## EROFS Support

gVisor supports EROFS (Enhanced Read-Only File System) rootfs and mounts. It is
a performant read-only filesystem and avoids having to talk to the host
filesystem (via host syscalls) at all. The EROFS image file is memory mapped
into the sentry and accessed via memory access by the sentry. It is ideal to
define your rootfs overlay's lower layer as EROFS. This also allows running
gVisor in gofer-less mode (given no other gofer mounts exist).

### EROFS rootfs

You can configure the rootfs overlay to have an EROFS lower layer by setting the
following annotations in the container spec:

```json
    "annotations": {
      "dev.gvisor.spec.rootfs.source": "/tmp/container_image.erofs",
      "dev.gvisor.spec.rootfs.type": "erofs",
      "dev.gvisor.spec.rootfs.overlay": "memory",
      "dev.gvisor.spec.rootfs.options": "size=2g"
    },
```

The `source` and `type` annotations are required. Other fields:

-   The `overlay` annotation is optional. By default, no overlay will be applied
    and you will have a read-only rootfs. It accepts one of the
    [backing mediums](#backing-mediums).
-   The `options` annotation is optional. It is a comma separated list of
    options. Currently only `size` option is supported. It can be used to define
    the size limit of tmpfs upper layer.

### EROFS Mounts

You can specify EROFS using 2 methods:

-   You can start your container with an EROFS mount by adding it in the
    container spec as a mount:

```json
    "mounts": [
    ...
        {
            "destination": "/foo",
            "type": "erofs",
            "source": "/tmp/foo.erofs"
        },
    ...
    ]
```

-   You can dynamically add an EROFS mount at runtime:

```
runsc --root=/path/to/rootdir debug --mount erofs:{source}:{destination}
```

[Production guide]: production.md
