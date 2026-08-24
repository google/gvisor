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

*   By default, filesystem snapshots include only root filesystem upper layers.
    Non-root tmpfs upper layers (created by the `-overlay2` flag with mount
    specifier `all`, by container-spec tmpfs mounts, or inferred from Kubernetes
    `emptyDir` volumes) can be included by passing `--path=all-tmpfs` to `runsc
    fscheckpoint`; see [Usage](#usage). This only includes tmpfs mounts that
    have a private (typically disk-backed) memory file. tmpfs mounts backed by
    the main (application) memory file, and tmpfs mounts created by sandboxed
    applications via `mount(2)`, are still excluded. Options to include these
    may be added in the future.

*   Filesystem snapshots can only be restored by the same runsc binary that
    produced the snapshot. This restriction may be removed in the future.

## Usage

To save a filesystem snapshot, use the `runsc fscheckpoint` command, passing the
directory that will contain the snapshot using the `--image-path` flag:

```bash
runsc fscheckpoint --image-path=<path> --path=/ <container ID>
```

By default, saving a filesystem snapshot causes the sandbox to exit. This
behavior can be disabled with the `--leave-running` flag.

By default (`--path=/`), only root filesystem upper layers are saved (across all
containers in the sandbox). The `--path` flag selects which tmpfs mounts to
save. It can be repeated to save multiple paths.

Format: `--path=[<container_id>:]<path>`

*   If `<container_id>` is omitted, the path is saved for all containers in the
    sandbox.

*   `--path=<dir>` saves the tmpfs mounted at `<dir>` (in every container). It
    must be a disk-backed tmpfs or overlayfs which has a disk-backed tmpfs as
    the upper layer.

*   `--path=all-tmpfs` saves all disk-backed tmpfs mounts in all containers.

*   `--path=container1:/data` saves the tmpfs mounted at `/data` in `container1`
    only.

To restore a filesystem snapshot, pass the directory containing the snapshot to
`runsc create` or `runsc run` using the `--fs-restore-image-path` flag:

```bash
runsc create --fs-restore-image-path=<path> <container ID>
```

## Reflink Snapshots

By default, saving a filesystem snapshot copies the contents of all saved files
while the sandbox is paused, so the pause duration is proportional to the
amount of saved data. Passing `--reflink` to `runsc fscheckpoint` instead
captures file contents by cloning each filesystem's disk-backed filestore file
using `ioctl(FICLONE)`, which shares extents copy-on-write at the host
filesystem level. Since cloning is a metadata operation, the sandbox pause
duration becomes proportional to the amount of filesystem *metadata* (number
of files) rather than data, typically reducing it by orders of magnitude.

```bash
runsc fscheckpoint --image-path=<path> --reflink <container ID>
```

Requirements and caveats:

*   The `--image-path` directory must be on the same host filesystem as the
    tmpfs filestore files, and that filesystem must support `FICLONE` (e.g.
    XFS with `reflink=1`, or Btrfs). ext4 does not support `FICLONE`.

*   Reflink snapshots use snapshot format version 2, comprising the manifest,
    multi-tar, and pages metadata files plus one `filestore.<i>.img` file per
    saved filesystem (instead of a single `pages.img`). Restore requires no
    additional flags: `runsc create --fs-restore-image-path` detects the
    format from the manifest. Restoring clones the saved filestore files back
    into place, so restore also completes without copying file contents when
    the snapshot directory is on the same host filesystem as the new sandbox's
    filestore files.

*   `--reflink` is incompatible with `--direct` and with checkpoints stored
    directly in GCS.

*   Reflink snapshots can currently only be taken with the `runsc
    fscheckpoint` command; the application-driven trigger
    (`/proc/gvisor/fscheckpoint`) always uses the copying format.

*   Snapshot files written by `--reflink` share disk extents with the live
    filestore files until either is modified or deleted. Writes made by the
    sandbox after a `--leave-running` snapshot incur extent-level
    copy-on-write cost in the host filesystem until the snapshot is deleted.

## Application-Driven Filesystem Checkpoint

gVisor also lets the workload *inside* the sandbox trigger filesystem
checkpoints, without any external call to `runsc`.

This functionality is configured entirely through OCI runtime spec
**annotations** and is exposed to the workload through files under
`/proc/gvisor/`.

### Enabling

Application-driven filesystem checkpointing is enabled by setting the
`dev.gvisor.internal.fscheckpoint.path` annotation on the **root/first
container**. This annotation serves two purposes:

-   It points to the directory where the checkpoint files will be written (the
    equivalent of the `--image-path` flag).
-   It causes the `/proc/gvisor/fscheckpoint` file to be created in the sandbox.

By default `/proc/gvisor/fscheckpoint` is read-only (mode `0444`): a workload
can read it to *wait* for the next checkpoint. To allow a container to *trigger*
a checkpoint, set `dev.gvisor.internal.fscheckpoint.enable=true` on that
container. This is a per-container setting.

> Note: The `path` annotation must be set on the root container; it configures
> the snapshot destination for the whole sandbox. The `enable` annotation is
> evaluated per container.

### Checkpoint options

The options normally passed as flags to `runsc fscheckpoint` are instead
provided as annotations on the root/first container:

Annotation                                | Description                                                                                                 | Default
----------------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------
`dev.gvisor.internal.fscheckpoint.path`   | Directory where filesystem checkpoint files are written. Required to enable.                                | (required)
`dev.gvisor.internal.fscheckpoint.enable` | Per-container; creates a writable `/proc/gvisor/fscheckpoint` so the workload can trigger an FS checkpoint. | `false`
`dev.gvisor.internal.fscheckpoint.resume` | Keep the sandbox running after the filesystem checkpoint (analogous to `--leave-running`).                  | `false`
`dev.gvisor.internal.fscheckpoint.direct` | Use `O_DIRECT` for filesystem checkpoint I/O.                                                               | `false`
`dev.gvisor.internal.fscheckpoint.paths`  | Comma-separated list of paths inside the containers to snapshot. Format: `[container_id:]path`.             | `/` (all containers)

### Triggering and waiting via `/proc/gvisor/fscheckpoint`

To trigger a filesystem checkpoint, write `1` to `/proc/gvisor/fscheckpoint` and
read it back; the read blocks until the operation finishes and returns `resume`
on success or `error` on failure.

Triggering a second save by writing to the same file will fail with `ENXIO`.

```bash
# Open FD 3, trigger a fs checkpoint, then read the outcome.
exec 3<>/proc/gvisor/fscheckpoint
echo 1 >&3
cat <&3   # blocks until resume completes, prints "resume" on success
```
