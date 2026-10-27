# Sandboxes Without a Root Container

[TOC]

`runsc` can boot a sandbox that has no root container. The sandbox starts empty:
it has no root filesystem, no process, and no gofer. You add containers to it
later, each with its own bundle.

This mode is off by default. You enable it with the `--no-root-container` flag
on `runsc create`, `runsc run`, and `runsc restore`.

## Why use it

A gVisor sandbox usually belongs to its first container. That container gives
the sandbox its root filesystem, its init process is PID 1, and the sandbox
stops when that process exits. In Kubernetes, the first container is the pause
container. Its only job is to keep the sandbox open.

A sandbox without a root container removes the pause container:

*   There is no pause image to pull or store.
*   The host runs fewer processes for each pod, and the sandbox starts and
    restores faster and uses less memory. See [Performance](#performance).
*   The sandbox lifetime is explicit. The sandbox continues to run with zero
    containers. It stops only when its owner stops it.

The mode is for runtimes and orchestrators that manage the pod sandbox
themselves and add containers to it, for example a runtime that implements the
containerd [Sandbox API][sandbox-api].

## Performance

A sandbox without a root container saves a fixed amount for each pod: one gofer
process and two systrap stub processes on the host, and the pause task in the
sentry. This gives 33% fewer host processes (9 to 6) and about 4% less host
memory for each pod, at every scale.

The latency gain increases with concurrency. With a hot cache, sandbox start is
16% faster for one pod, and 29% to 36% faster when 32 to 64 pods start at the
same time. Restore is 10% to 17% faster, with or without `--background`. Tail
latency (p99) improves by similar amounts.

The mode gives the most benefit on dense nodes with many small pods that start
or restore at the same time from a warm cache, for example serverless platforms
and agent sandboxes.

These results compare a sandbox without a root container to a sandbox with a
pause container. They were measured with the systrap platform on one host, so
your results can be different.

## Usage

You need root, an OCI bundle for the sandbox, and an OCI bundle for each
application container.

The sandbox bundle has a `config.json` with no `process` and no `root`. `runsc`
refuses a sandbox spec that has either of them. The minimum spec is:

```bash
mkdir -p /tmp/pod
echo '{"ociVersion": "1.0.0"}' > /tmp/pod/config.json
```

The application container bundle is a usual bundle with two annotations:

*   `io.kubernetes.cri.container-type`, set to `container`, tells `runsc` to add
    the container to an existing sandbox. Without it, `runsc` creates a new
    sandbox.
*   `io.kubernetes.cri.sandbox-id` names that sandbox. It is required.

```bash
mkdir -p /tmp/cont/rootfs/bin
cp /bin/busybox /tmp/cont/rootfs/bin/
for c in sh sleep ps; do ln -sf busybox /tmp/cont/rootfs/bin/$c; done

cat > /tmp/cont/config.json <<'EOF'
{
  "ociVersion": "1.0.0",
  "annotations": {
    "io.kubernetes.cri.container-type": "container",
    "io.kubernetes.cri.sandbox-id": "pod1"
  },
  "process": {"cwd": "/", "args": ["/bin/sleep", "1000"], "user": {"uid": 0, "gid": 0}},
  "root": {"path": "rootfs", "readonly": true}
}
EOF
```

Create and start the sandbox, then add the container:

```bash
runsc create --no-root-container --bundle /tmp/pod pod1
runsc start pod1

runsc create --bundle /tmp/cont c1
runsc start c1
```

The sandbox and the container share one sentry. `runsc list` shows the sentry
PID for the sandbox, because the sandbox has no process of its own:

```
ID      PID       STATUS    BUNDLE     CREATED                          OWNER
c1      1030939   running   /tmp/cont  2026-10-20T22:21:19.976816285Z   root
pod1    1030939   running   /tmp/pod   2026-10-20T22:21:19.922968869Z   root
```

The first process in the pod is PID 2:

```
$ runsc exec c1 /bin/ps
PID   USER     COMMAND
    2 0        /bin/sleep 1000
    3 0        /bin/ps
```

### Stop the sandbox

Stop and delete the containers first. Then delete the sandbox:

```bash
runsc kill c1 KILL
runsc delete c1
runsc delete pod1
```

`runsc delete pod1` does not need `--force`, because the sandbox never stops on
its own. If a container in the sandbox is running or paused, `runsc delete pod1`
fails. `runsc delete --force pod1` stops the sandbox and all of its containers.

The sandbox process also stops when it receives `SIGTERM` or `SIGINT`. It
ignores other signals, except the debug signals that `--panic-signal` and
`--dump-goroutines-signal` set.

### Networking

The network namespace belongs to the sandbox. Put it in the sandbox spec:

```json
{
  "ociVersion": "1.0.0",
  "linux": {
    "namespaces": [{"type": "network", "path": "/var/run/netns/pod1-netns"}]
  }
}
```

All containers in the sandbox share one network stack, as in any pod.

### Pod volumes

Put the [pod mount hints](containerd/configuration.md)
(`dev.gvisor.spec.mount.*` annotations) in the sandbox spec. `runsc` reads them
from the sandbox spec, as it reads them from the pause container spec in the
usual mode.

### Checkpoint and restore

A sandbox without a root container supports
[checkpoint/restore](checkpoint_restore.md). Checkpoint the sandbox by its ID.
The ID of a container in the sandbox also works. Both save the full sandbox:

```bash
runsc checkpoint --image-path=/tmp/img pod1
```

By default, the sandbox and its containers stop after the checkpoint, but their
state remains. Delete them before you restore with the same IDs:

```bash
runsc delete c1
runsc delete pod1
```

Restore the sandbox first, with `--no-root-container`. Then restore each
container from the same image:

```bash
runsc restore --no-root-container --detach --bundle /tmp/pod --image-path=/tmp/img pod1
runsc restore --detach --bundle /tmp/cont --image-path=/tmp/img c1
```

A checkpoint image restores only into a sandbox that boots in the same mode. You
cannot restore a checkpoint of a pause-container sandbox with
`--no-root-container`, or the reverse.

## Differences from a sandbox with a root container

*   **No PID 1.** No process in the sandbox PID namespace is PID 1. No container
    is the pod's init, and the pod does not stop when a container exits. An
    orphan process has no parent, and the sentry releases it when it exits, so
    it does not stay as a zombie. A container that asks for its own PID
    namespace gets one, and its first process is PID 1 in that namespace.
*   **The sandbox ID is not a container.** These commands fail on a started
    sandbox:
    *   `runsc kill`. Use `runsc delete` to stop the sandbox.
    *   `runsc exec`. Use the ID of a container in the sandbox.
    *   `runsc checkpoint --save-restore-exec-argv`. The save/restore program
        needs the init process of a container, and the sandbox has none. Use the
        ID of a container in the sandbox. The checkpoint still includes the full
        sandbox.
*   **No terminal or passed files for the sandbox.** With `--no-root-container`,
    `runsc create`, `runsc run`, and `runsc restore` refuse `--console-socket`
    and `--pass-fd`, and `runsc run` refuses `--exec-fd`, because the sandbox
    has no process. Containers in the sandbox still accept them: give
    `--console-socket` to `runsc create`, and `--pass-fd` or `--exec-fd` to
    `runsc exec`.
*   **`runsc wait` on the sandbox ID** returns status 0 when the sandbox stops.
    If a restore fails, it returns status 1.

[sandbox-api]: https://github.com/containerd/containerd/blob/main/docs/sandbox-api.md
