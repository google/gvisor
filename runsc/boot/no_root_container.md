# Sandboxes with no root container

`runsc create --no-root-container` boots a sandbox that contains nothing: no
root container, no root filesystem, no process, and no gofer. The sentry comes
up empty and containers are added to it afterwards, each with its own bundle.

This is the pod without a pause container. Normally the first container `runsc`
is asked to run owns the sandbox: it provides the rootfs the sandbox is built
from, its init process is PID 1, and the sandbox lives exactly as long as it
does. Under CRI that first container is the pause container, an image whose only
job is to exist. With `--no-root-container` there is no such container, and
nothing inside the sandbox owns its lifetime: whoever created the sandbox is
responsible for deleting it.

The mode exists for the containerd Sandbox API, where containerd manages the pod
sandbox itself and gives the runtime no spec to run. That is the only intended
caller. `--no-root-container` is not a user-facing workflow; it is what makes the
mode reachable without containerd, for testing and for the walkthrough below.

## Driving it by hand

You need root and a `runsc` binary. Two bundles: one for the sandbox, one for a
container to put in it.

The sandbox bundle needs a `config.json` with no `process` and no `root` --
there is nothing to run and nothing to run it on. That leaves very little:

```bash
mkdir -p /tmp/pod
echo '{"ociVersion": "1.0.0"}' > /tmp/pod/config.json
```

The container bundle is an ordinary one. The `sandbox-id` annotation is what
puts the container in the sandbox rather than in one of its own:

```bash
mkdir -p /tmp/cont/rootfs/bin
cp /bin/busybox /tmp/cont/rootfs/bin/
for c in sh sleep ps ls ip; do ln -sf busybox /tmp/cont/rootfs/bin/$c; done

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

Boot the sandbox, then add the container to it:

```bash
runsc create --no-root-container --bundle /tmp/pod pod1
runsc start pod1

runsc create --bundle /tmp/cont c1
runsc start c1
```

`runsc list` shows both sharing one sentry -- the sandbox reports the sentry's
PID because it has no process of its own to report:

```
ID     PID       STATUS    BUNDLE      CREATED                          OWNER
c1     1733764   running   /tmp/cont   2026-08-05T23:47:10.995780167Z   root
pod1   1733764   running   /tmp/pod    2026-08-05T23:47:10.848767233Z   root
```

`runsc exec c1 /bin/ps` shows the pod has no init:

```
PID   USER     COMMAND
    2 0        /bin/sleep 1000
    3 0        /bin/ps
```

The first process in the pod is PID 2, not PID 1. PID 1 is reserved and never
handed out, precisely because no container should become the pod's init: if one
did, the pod would die with it. Orphans have no init to reparent to and are
reparented to nil instead, which `exitNotifyLocked` already handles by acking
the exit itself, so they do not linger as zombies waiting to be reaped. See
`PIDNamespace.ReserveInitTID`.

## Stopping it

Tear the pod down container-first, and delete the sandbox last:

```bash
runsc kill c1 KILL
runsc delete c1
runsc delete pod1
```

`runsc kill pod1` does not apply and says so: there is no root container process
to deliver a signal to. This is also why `runsc delete pod1` works while the
sandbox is still running, where deleting a running container would normally
require `--force`: such a sandbox can never stop on its own, so requiring
`--force` would mean requiring it always.

Deleting the sandbox while it still holds containers takes them down with it, so
that does require `--force`:

```bash
runsc delete pod1
cannot delete sandbox "pod1" while it still holds 1 container(s) without --force flag

runsc delete --force pod1   # destroys the sandbox and everything in it
runsc delete c1             # container state files outlive the sandbox
```

## Networking

Networking works as it does for any other pod, because the network namespace
belongs to the sandbox and never belonged to the root container. Name it in the
*sandbox* bundle's `config.json`:

```json
{
  "ociVersion": "1.0.0",
  "linux": {
    "namespaces": [{"type": "network", "path": "/var/run/netns/pod1-netns"}]
  }
}
```

The sentry starts inside that namespace and copies its interfaces and routes
into netstack. Containers added to the sandbox share that one network stack,
which is what makes them a pod. Under CRI the path is the network namespace CNI
created for the pod.

Note that `runsc` takes the addresses over: it removes them from the host-side
interfaces in the namespace, so if you boot a second sandbox in a namespace you
set up by hand, re-add the addresses first.

## What is different from a pod with a pause container

*   There is no pause container, so no pause image to pull and no container
    whose only job is to hold the sandbox open.
*   The pod has no PID 1. Processes in containers sharing the pod's PID
    namespace still see each other, which is what PID namespace sharing is for,
    but there is no init to reap them.
*   The sandbox outlives its containers. It stays up with zero containers in it
    and accepts new ones.
*   `runsc kill` does not apply to the sandbox; `runsc delete` stops it.
*   Checkpoint and restore are refused. See
    `Container.checkpointRestoreSupported`.
