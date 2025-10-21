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

### Limitation

It is not supported on the arm64 architecture.

[leave-running]: https://github.com/moby/moby/pull/37360
[checkpoint-dir]: https://github.com/moby/moby/issues/37344
