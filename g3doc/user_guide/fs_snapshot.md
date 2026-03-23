# Filesystem Snapshots

[TOC]

gVisor has the ability to save changes made to root filesystems in a *filesystem
snapshot*, and subsequently restore those changes in new sandboxes.

Compared to [rootfs tar snapshots](rootfs_snapshot.md):

*   Filesystem snapshots include root filesystem changes in all containers in a
    sandbox, rather than a single container.

*   Filesystem snapshots comprise multiple files in a directory.

*   Save and restore throughput is higher for filesystem snapshots than for
    rootfs tar snapshots, subject to disk throughput limits.

*   Containers can begin execution while filesystem snapshot restore is in
    progress, but must wait for rootfs tar snapshot restore to complete.

*   Filesystem snapshots store sparse files more efficiently than rootfs tar
    snapshots.

## Prerequisites

*   Container root filesystems must be an overlay whose upper layer is
    disk-backed tmpfs. This behavior is enabled by default, via the default
    value of the `runsc -overlay2` flag. The requirement that the tmpfs is
    disk-backed may be removed in the future.

*   Filesystem snapshots do not include non-root tmpfs upper layers created by
    the `-overlay2` flag with mount specifier `all`; tmpfs mounts specified by a
    container spec; tmpfs mounts inferred from Kubernetes `emptyDir` volumes; or
    tmpfs mounts created by sandboxed applications. Options to include these may
    be added in the future.

*   Filesystem snapshots can only be restored by the same runsc binary that
    produced the snapshot. This restriction may be removed in the future.

## Usage

To save a filesystem snapshot, use the `runsc fscheckpoint` command, passing the
directory that will contain the snapshot using the `--image-path` flag:

```bash
runsc fscheckpoint --image-path=<path> <container ID>
```

By default, saving a filesystem snapshot causes the sandbox to exit. This
behavior can be disabled with the `--leave-running` flag.

To restore a filesystem snapshot, pass the directory containing the snapshot to
`runsc create` or `runsc run` using the `--fs-restore-image-path` flag:

```bash
runsc create --fs-restore-image-path=<path> <container ID>
```
