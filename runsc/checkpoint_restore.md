# runsc checkpoint/restore

gVisor supports checkpointing and restoring containers. A container’s state can
be checkpointed and later restored into one or more containers. This can be used
to save work and time in cases of failure and allow for container migration. A
single container can perform slower setup tasks and then be checkpointed so that
many containers with the same task can be “restored” and started more quickly.

### How to checkpoint/restore

To use the runsc checkpoint command, first run a container.

```sh
runsc run <container id>
```

To checkpoint the container, the --image-path flag must be provided. This is the
directory path within which the checkpoint state-file will be created. The file
will be called checkpoint.img and necessary directories will be created if they
do not yet exist.

> Note: Two checkpoints cannot be saved to the save directory; every image-path
provided must be unique.

```sh
runsc checkpoint --image-path=<path> <container id>
```

There is also an optional --leave-running flag that allows the container to
continue to run after the checkpoint has been made. (By default, containers stop
their processes after committing a checkpoint.)

> Note: All top-level runsc flags needed when calling run must be provided to
checkpoint if --leave-running is used.

> Note: --leave-running functions by causing an immediate restore so the
container, although will maintain its given container id, may have a different
process id.

```sh
runsc checkpoint --image-path=<path> --leave-running <container id>
```

To restore, provide the image path to the checkpoint.img file created during the
checkpoint. Because containers stop by default after checkpointing, restore
needs to happen in a new container (restore is a command which parallels start).

```sh
runsc create <container id>

runsc restore --image-path=<path> <container id>
```

### How to use checkpoint/restore in Docker:

Currently checkpoint/restore through runsc is not entirely compatible with
Docker, although there has been progress made from both gVisor and Docker to
enable compatibility. Here, we document the ideal workflow.

To run with Docker, first follow the [instructions](https://gvisor.googlesource.com/gvisor/+/master/README.md#configuring-docker) to use runsc as a runtime.

Run a container:

```sh
docker run [options] --runtime=runsc <image>`
```

Checkpoint a container:

```sh
docker checkpoint create <container> <checkpoint_name>`
```

Create a new container into which to restore:

```sh
docker create [options] --runtime=runsc <image>
```

Restore a container:

```sh
docker start --checkpoint --checkpoint-dir=<directory> <container>
```

**Issues Preventing Compatibility with Docker**
1. [Moby #37360][leave-running]

Docker version 18.03.0-ce and earlier hangs when checkpointing and
does not create the checkpoint. To successfully use this feature, install a
custom version of docker-ce from the moby repository. This issue is caused by an
improper implementation of the `--leave-running` flag. This issue is now fixed
although is not yet part of an official release.

2. Docker does not support restoration into new containers.

Docker currently expects the container which created the checkpoint
to be the same container used to restore which is not possible in runsc. When
Docker supports container migration and therefore restoration into new
containers, this will be the flow.

3. [Moby #37344][checkpoint-dir]

Docker does not currently support the `--checkpoint-dir` flag but this will be
required when restoring from a checkpoint made in another container.

[leave-running]: https://github.com/moby/moby/pull/37360
[checkpoint-dir]: https://github.com/moby/moby/issues/37344
