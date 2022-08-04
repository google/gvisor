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
`--overlay2=root:/dir/path` in `runtimeArgs`. `/dir/path` can be any existing
directory inside which the tmpfs filestore file will be created. When the
container exits, this filestore file will be destroyed.

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
