# Checkpoint/Restore

[TOC]

gVisor has the ability to checkpoint a process, save its current state in a
state file, and restore into a new container using the state file.

## How to use checkpoint/restore

Checkpoint/restore functionality is currently available via raw `runsc`
commands. To use the checkpoint command, first run a container.

```bash
runsc run <container id>
```

To checkpoint the container, the `--image-path` flag must be provided. This is
the directory path within which the checkpoint related files will be created.
All necessary directories will be created if they do not yet exist.

> Note: Two checkpoints cannot be saved to the same directory; every image-path
> provided must be unique.

```bash
runsc checkpoint --image-path=<path> <container id>
```

There is also an optional `--leave-running` flag that allows the container to
continue to run after the checkpoint has been made. (By default, containers stop
their processes after committing a checkpoint.)

> Note: All top-level runsc flags needed when calling run must be provided to
> checkpoint if `--leave-running` is used.

> Note: `--leave-running` functions by causing an immediate restore so the
> container, although will maintain its given container id, may have a different
> process id.

```bash
runsc checkpoint --image-path=<path> --leave-running <container id>
```

To restore, provide the image path to the directory containing all the files
created during the checkpoint. Because containers stop by default after
checkpointing, restore needs to happen in a new container (restore is a command
which parallels start).

```bash
runsc create <container id>

runsc restore --image-path=<path> <container id>
```

> Note: All top-level runsc flags needed when calling run must be provided to
> `restore`.

## Optimizations

gVisor supports several performance optimizations during checkpoint and restore.
These can be configured via flags provided to the `runsc checkpoint` and `runsc
restore` commands.

### Compression

By providing the `--compression` flag to `runsc checkpoint`, users can specify
the compression level of the generated snapshot files. Supported values are
`none` (default) and `flate-best-speed`.

Note that `--compression=none` consumes less CPU and is faster. The generated
snapshot contains multiple files. As a result, it allows the kernel and memory
restores to proceed in parallel. Furthermore, several other optimizations
described below require `--compression=none`.

### Exclude Committed Zero Pages

By providing the `--exclude-committed-zero-pages` flag to `runsc checkpoint`,
gVisor skips saving memory pages that are committed but contain only zeros. This
can significantly reduce the checkpoint size for applications that have large,
zero-filled memory regions (like LLMs), thereby speeding up restore. However, it
may increase checkpoint duration, as it requires scanning all committed pages to
determine if they are zero-filled.

### Direct I/O

By providing the `--direct` flag to `runsc checkpoint` or `runsc restore`,
gVisor uses `O_DIRECT` when writing or reading the pages file. This bypasses the
host page cache. This optimization requires `--compression=none` during
checkpoint. This is only supported on filesystems that support direct I/O.

This is particularly advantageous when the snapshot is being read for the first
time from disk and will not be restored on the same machine again, making
caching in the host page cache undesirable.

### Background Restore

By providing the `--background` flag to `runsc restore`, the application can
start execution as soon as the kernel state is loaded. The remaining application
memory and file data are restored asynchronously in the background while the
application is running. This optimization requires `--compression=none` during
checkpoint.

If the application accesses a memory page that has not yet been restored, gVisor
prioritizes loading that page immediately to unblock the application thread.
This can dramatically reduce the "Time to First Instruction" for large
applications.

Note that when this is enabled, the sandbox may continue to have an open FD on
the snapshot files even after the sandboxed application has started. This means
that until the sandbox has fully restored (async page loading has completed):

-   Deleting the pages file may not free disk space immediately on POSIX
    filesystems.
-   Deleting the pages file may not be possible on non-POSIX filesystems.
-   The mount containing the snapshot files cannot be unmounted.

You can use `runsc wait --restore` to wait for restore to complete fully, after
which you can clean up the `--image-path` directory if necessary.

## How to use checkpoint/restore in Docker:

Run a container:

```bash
docker run [options] --runtime=runsc --name=<container-name> <image>
```

Checkpoint the container:

```bash
docker checkpoint create <container-name> <checkpoint-name>
```

Restore into the same container:

```bash
docker start --checkpoint <checkpoint-name> <container-name>
```

### Issues Preventing Compatibility with Docker

-   **[Moby #37360][leave-running]:** Docker version 18.03.0-ce and earlier
    hangs when checkpointing and does not create the checkpoint. To successfully
    use this feature, install a custom version of docker-ce from the moby
    repository. This issue is caused by an improper implementation of the
    `--leave-running` flag. This issue is fixed in newer releases.
-   **Docker does not support restoration into new containers:** Docker
    currently expects the container which created the checkpoint to be the same
    container used to restore. This is needed to support container migration.
-   **[Moby #37344][checkpoint-dir]:** Docker does not currently support the
    `--checkpoint-dir` flag but this will be required when restoring from a
    checkpoint made in another container.

## Networking

Checkpoint/restore is supported with `--network=sandbox` (default),
`--network=none`, and `--network=host`.

With `--network=host`, host sockets cannot be saved, so:

-   Checkpoint with `--leave-running` does not touch the running sandbox's
    sockets. It keeps using them as before.
-   TCP listening sockets are re-created during restore and keep accepting new
    connections. Connections that were pending in the backlog at checkpoint time
    are lost. If the listen address cannot be bound on the restoring host, the
    listener socket will fail to restore (subsequent operations on it will
    return errors), but the sandbox restore operation will still succeed.
-   Sockets that were connected at checkpoint time return `ECONNRESET`, and
    `epoll_wait` on them returns `EPOLLERR | EPOLLHUP` immediately. Applications
    must reconnect after restore.
-   Network configuration visible inside the sandbox (interface statistics, TCP
    buffer sizes) reflects the host the sandbox was restored on.

## Checkpoint & Restore with different CPU features

When restoring a state file, gVisor verifies that the target host machine
possesses all the CPU features enabled on the machine where the checkpoint
snapshot was created.

gVisor allows users to specify a list of *allowed* CPU features using the
annotation `dev.gvisor.internal.cpufeatures`. Only the host CPU features present
in this annotation list will be enabled. By doing this, users are able to
stabilize the list of CPU features that will be exposed to applications in the
sandbox, which makes it possible to checkpoint and restore among machines with
different set of CPU features.

CPU features in the annotation should be comma-separated. A comprehensive list
of all supported CPU features can be found
[here](https://github.com/google/gvisor/blob/61f4c77225e1f5128cad8982f3af0d4278494bd4/pkg/cpuid/features_amd64.go#L457).

The runsc command `runsc cpu-features` lists all CPU features on the current
machine.

## GPU Checkpoint/Restore

gVisor supports checkpointing and restoring containers that use GPUs by
leveraging [cuda-checkpoint](https://github.com/NVIDIA/cuda-checkpoint).

When a snapshot is created via `runsc checkpoint`, the user can provide the
`--cuda-checkpoint-path` flag to indicate the path to the `cuda-checkpoint`
binary in the container filesystem. This enables `cuda-checkpoint` automation.

Before pausing the container, gVisor will collect all the CUDA processes in the
sandbox and checkpoint them using `cuda-checkpoint`. Note that `cuda-checkpoint`
is invoked in parallel across all processes for performance. Once all
`cuda-checkpoint` invocations succeed, the regular gVisor checkpointing
procedure continues.

On restore, after the kernel is restored and started, all CUDA processes which
were checkpointed earlier are toggled back on using `cuda-checkpoint`. `runsc
restore` does not require any special flags. If the snapshot was created with
`runsc checkpoint --cuda-checkpoint-path`, then the same configuration will
automatically be used on restore.

### Limitation

GPU checkpoint/restore is not supported on the arm64 architecture due to lack of
support in [cuda-checkpoint](https://github.com/NVIDIA/cuda-checkpoint).

[leave-running]: https://github.com/moby/moby/pull/37360
[checkpoint-dir]: https://github.com/moby/moby/issues/37344

## Application-Driven Checkpoint/Restore

In addition to the `runsc checkpoint` CLI command, gVisor lets the workload
*inside* the sandbox trigger checkpoints and synchronize with restore, without
any external call to `runsc`. This is useful for applications that want to
checkpoint at a specific, self-determined point (for example, after warming up a
cache or finishing initialization) and for applications that need to react to
being restored.

This functionality is configured entirely through OCI runtime spec
**annotations** and is exposed to the workload through files under
`/proc/gvisor/`. No new `runsc` flags are involved.

### Enabling

Application-driven checkpointing is enabled by setting the
`dev.gvisor.internal.checkpoint.path` annotation on the **root/first
container**. This annotation serves two purposes:

-   It points to the directory where the checkpoint files will be written (the
    equivalent of the `--image-path` flag).
-   It causes the `/proc/gvisor/checkpoint` and `/proc/gvisor/spec_environ`
    files to be created in the sandbox.

By default `/proc/gvisor/checkpoint` is read-only (mode `0444`): a workload can
read it to *wait* for the next resume/restore. To allow a container to *trigger*
a checkpoint, set `dev.gvisor.internal.checkpoint.enable=true` on that
container. This is a per-container setting, so you can let some containers
trigger checkpoints while others can only observe them.

> Note: The `path` annotation must be set on the root container; it configures
> the snapshot destination for the whole sandbox. The `enable` annotation is
> evaluated per container.

### Checkpoint options

When checkpointing is driven by the workload, the options normally passed as
flags to `runsc checkpoint` are instead provided as annotations on the
root/first container:

Annotation                                                    | Description                                                                                           | Default
------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | -------
`dev.gvisor.internal.checkpoint.path`                         | Directory where checkpoint files are written. Required to enable.                                     | (required)
`dev.gvisor.internal.checkpoint.enable`                       | Per-container; makes `/proc/gvisor/checkpoint` writable so the workload can trigger a checkpoint.     | `false`
`dev.gvisor.internal.checkpoint.resume`                       | Keep the sandbox running after the checkpoint (analogous to `--leave-running`).                       | `false`
`dev.gvisor.internal.checkpoint.compression`                  | Compression level: `none` or `flate-best-speed` (see [Compression](#compression)).                    | none
`dev.gvisor.internal.checkpoint.direct`                       | Use `O_DIRECT` for checkpoint I/O (see [Direct I/O](#direct-io)).                                     | `false`
`dev.gvisor.internal.checkpoint.exclude-committed-zero-pages` | Skip saving committed zero pages (see [Exclude Committed Zero Pages](#exclude-committed-zero-pages)). | `false`
`dev.gvisor.internal.checkpoint.cuda-checkpoint-path`         | Path to the `cuda-checkpoint` binary (see [GPU Checkpoint/Restore](#gpu-checkpointrestore)).          | (unset)
`dev.gvisor.internal.checkpoint.cuda-checkpoint-sequential`   | Run `cuda-checkpoint` sequentially instead of in parallel.                                            | `false`
`dev.gvisor.internal.checkpoint.save-restore-exec-argv`       | Argv of a binary to exec around save/restore.                                                         | (unset)
`dev.gvisor.internal.checkpoint.save-restore-exec-timeout`    | Timeout for the save/restore exec binary (e.g. `30s`).                                                | 10 minutes

### Triggering and waiting via `/proc/gvisor/checkpoint`

The `/proc/gvisor/checkpoint` file is the workload's interface to the
checkpoint/restore machinery. It behaves like a character device with the
following protocol:

1.  **Open** the file. The open registers interest in the *next* checkpoint.
    This means you can open the file and then trigger a checkpoint without
    racing against it completing.
2.  **Write** `1` (or `1\n`, so `echo 1` works) to trigger a checkpoint. Writing
    requires `dev.gvisor.internal.checkpoint.enable=true`. Writing is optional —
    a process can simply read the file to passively wait for a checkpoint
    triggered by some other process. Triggering a second save by writing to the
    same file will fail with `ENXIO`.
3.  **Read** the file. The read blocks until the checkpoint completes and then
    returns one of the following lines:
    -   `resume` — the checkpoint completed and the original workload has
        resumed running (this is what the process that triggered the checkpoint
        sees when the sandbox keeps running).
    -   `restore` — execution is continuing inside a freshly *restored*
        instance, i.e. this process is running in the restored sandbox.
    -   `error` — the checkpoint failed; the workload resumes running anyway.

After the result is determined, reads always return the same value. To wait for
a *subsequent* checkpoint, the file must be opened again.

The `resume` vs. `restore` distinction lets a workload tell whether it is the
original (post-checkpoint) process or the restored copy, which is handy for
performing different post-checkpoint vs. post-restore actions on the same code
path.

For example, from a shell inside an enabled container:

```bash
# Open FD 3, trigger a checkpoint, then read the outcome.
exec 3<>/proc/gvisor/checkpoint
echo 1 >&3
cat <&3   # blocks until resume/restore completes, prints "resume" or "restore"
```

### Reading restore-time environment via `/proc/gvisor/spec_environ`

When application-driven checkpointing is enabled, gVisor also exposes
`/proc/gvisor/spec_environ`. It contains the environment variables from the
container's spec (NULL-separated, in the same format as `/proc/<pid>/environ`).

Because the environment variables in the spec used to *restore* a container can
differ from the one used to create it, this file gives the workload a way to
read environment variables supplied at restore time. A common pattern is to wait
on `/proc/gvisor/checkpoint`, and once it reports `restore`, re-read
`/proc/gvisor/spec_environ` to pick up new configuration injected by the
restoring environment.
