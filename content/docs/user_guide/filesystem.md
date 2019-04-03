+++
title = "Filesystem"
weight = 45
+++
gVisor accesses the filesystem through a file proxy, called the Gofer. The gofer
runs as a separate process, that is isolated from the sandbox. Gofer instances
communicate with their respective sentry using the 9P protocol. For a more detailed
explanation see [Overview > Gofer](../../architecture_guide/overview/#gofer).

## Sandbox overlay

To isolate the host filesystem from the sandbox, you can set a writable tmpfs overlay
on top of the entire filesystem. All modifications are made to the overlay, keeping
the host filesystem unmodified.

> Note: All created and modified files are stored in memory inside the sandbox.

To use the tmpfs overlay, add the following `runtimeArgs` to your Docker configuration
(`/etc/docker/daemon.json`) and restart the Docker daemon:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--overlay"
            ]
       }
    }
}
```

## Shared root filesystem

The root filesystem is where the image is extracted and is not generally modified
from outside the sandbox. This allows for some optimizations, like skipping checks
to determine if a directory has changed since the last time it was cached, thus
missing updates that may have happened. If you need to `docker cp` files inside the
root filesystem, you may want to enable shared mode. Just be aware that file system
access will be slower due to the extra checks that are required.

> Note: External mounts are always shared.

To use set the root filesystem shared, add the following `runtimeArgs` to your Docker
configuration (`/etc/docker/daemon.json`) and restart the Docker daemon:

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
