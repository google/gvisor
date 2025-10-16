# Rootfs Snapshot

[TOC]

gVisor allows users to snapshot changes made to the root filesystem and save
them to a tar file. These changes in the tar file can then be applied to a new
sandbox upon creation.

## Prerequisite

*   Rootfs must be overlayfs whose upper layer is tmpfs (this is the default
    rootfs configuration)

## How to snapshot

The snapshotting function is available via `runsc` commands. To run the command,
you will start a gVisor container, create a directory and a new file at rootfs:

```
$ docker run --rm -it --runtime=runsc alpine
/ # mkdir dir
/ # echo "hello world" > dir/file
```

To take a snapshot of the rootfs change, you will use `runsc tar rootfs-upper`
command, the tar file will be saved to the path that is specified in `--file`
flag:

```
$ sudo runsc --root=/var/run/docker/runtime-runc/moby tar rootfs-upper --file /tmp/rootfs.tar ddcbc9293778154db0f31068342adb5b1c08087ca94bfcef9070d23b44fbf2e8
```

You can observe the tar file as:

```
$ tar -tvf /tmp/rootfs.tar
drwxr-xr-x 0/0               0 2025-10-10 23:27 ./
drwx------ 0/0               0 2025-10-10 23:27 ./root/
-rw------- 0/0              41 2025-10-10 23:27 ./root/.ash_history
drwxr-xr-x 0/0               0 2025-10-10 23:27 ./dir/
-rw-r--r-- 0/0              12 2025-10-10 23:27 ./dir/file
```

You could also observe the file data from the tar file as:

```
$ tar -xf /tmp/rootfs.tar ./dir/file -O
hello world
```

## How to start a container with the tar file

To start a new gVisor sandbox with the tar file we just get, you will need
provide the annotation to OCI runtime spec, the key is
`dev.gvisor.tar.rootfs.upper`, the value is the path to the tar file.

### Start with Docker

Since the tar file path is provided via OCI spec's annotation, it is compatible
with Docker client when the runtime is gVisor. You can pass the annotation via
Docker commad and observe the file change as:

```
$ docker run --rm --runtime=runsc --annotation "dev.gvisor.tar.rootfs.upper"="/tmp/rootfs.tar" alpine cat /dir/file
hello world
```

### Start with OCI

You can add annotation to the bundle's `config.json` as:

```json
    "annotations": {
      "dev.gvisor.tar.rootfs.upper": "/tmp/rootfs.tar"
    },
```

Then you can start a new sandbox and observe the file changes from the previous
sandbox:

```
$ sudo runsc run -detach=true alpine
$ sudo runsc exec alpine cat /dir/file
hello world
```

> Please make sure you kill and delete the sandbox after the experiment.

## Limitation

*   Snapshotting is only supported for single-container sandboxes.
