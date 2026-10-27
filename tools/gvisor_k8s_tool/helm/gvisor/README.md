# Kubernetes installation

This chart installs a complete gVisor release on selected nodes and configures
its containerd runtime handler. Applications request gVisor through a
RuntimeClass. The cluster's default runtime stays unchanged.

## Requirements

Use fresh or drained Linux nodes that meet the [gVisor system
requirements](https://gvisor.dev/docs/user_guide/install/). The image supports
amd64 and arm64. The installer requires:

- Containerd running directly as a systemd service with `KillMode=process`.
  The selected CRI socket must belong to that process and serve the installer
  pod. Wrapper services such as k3s are not supported.
- Containerd configuration version 2 or 3, with CRI enabled. The installer
  rejects an existing handler with the requested name unless its own persistent
  state identifies it as an installation that it manages.
- Writable host paths and permission to run a privileged pod with the host PID
  namespace. The pod mounts the host root at `/host` and uses `nsenter` to run
  host commands.

Helm 3 and Helm 4 can install the chart. `runsc setup-k8s` also requires kubectl.
Use a kubectl version compatible with your Kubernetes API server.

Cloud node pools are not provisioned or certified by this chart. Managed
services, immutable operating systems, generated containerd configurations and
another component managing the same handler require separate validation. GKE
Sandbox has its own installation lifecycle.

## Install

The source chart requires an explicit installer image repository. Build the
[installer image](https://github.com/google/gvisor/blob/master/images/gvisor-installer/README.md) from the same
source as the chart, or use matching published release artifacts. Publication
sets the chart version, application version and image tag together.

```sh
helm upgrade --install gvisor ./tools/gvisor_k8s_tool/helm/gvisor \
  --namespace kube-system \
  --set image.repository=REGISTRY/gvisor-installer \
  --set image.tag=release-YYYYMMDD.PATCH \
  --wait --timeout 10m
kubectl --namespace kube-system rollout status daemonset/gvisor-gvisor \
  --timeout 10m
```

The rollout check is required with Helm 3. Its `--wait` check permits one
unready DaemonSet pod with this chart's update strategy, even on a single-node
pool. `runsc setup-k8s` runs both commands and reports failure if either fails:

```sh
runsc setup-k8s --chart=oci://REGISTRY/CHART_NAMESPACE/gvisor \
  --values=installer-values.yaml --kube-context=my-cluster
```

For remote charts, the command selects the chart version matching the runsc
release. Development builds require `--chart-version` or a local chart path.
`--timeout` bounds the whole operation. No automatic Helm rollback is requested.
A timeout leaves the installer running so its logs and state can be inspected.
Both tools use `KUBECONFIG`. `HELM_KUBECONTEXT` supplies the default context.
Helm-specific server and authentication environment overrides are rejected.
Put those settings in kubeconfig so both tools use the same connection.

The default RuntimeClass is `gvisor`, with containerd handler `runsc`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sandbox
spec:
  runtimeClassName: gvisor
  containers:
    - name: app
      image: busybox:1.37.0
      command: ["sleep", "3600"]
```

## Node selection

By default, the chart selects Linux amd64 and arm64 nodes except those labeled
`gvisor.dev/install=disabled`. It adds no tolerations. A control-plane taint
therefore excludes control-plane nodes unless a matching toleration is supplied.
To restrict installation to a node pool, set values such as:

```yaml
nodeSelector:
  sandbox-pool: "true"
```

Set `tolerations` explicitly if that pool is tainted. Label a node to stop
management, or remove the label to resume it:

```sh
kubectl label node NODE gvisor.dev/install=disabled
kubectl label node NODE gvisor.dev/install-
```

Stopping management preserves the host installation and its last reported
labels. It does not prevent workloads from using that runtime. Cordon or drain
the node if workload scheduling must stop.

The installer publishes `gvisor.dev/ready=true` after verifying containerd's
loaded handler. The RuntimeClass selects that label. During an unsuccessful
upgrade, a verified previous installation can remain available while the
installer pod stays unready because the requested version has not converged.
The label is the last observed status, not an independent health controller.

The chart uses fixed cluster RBAC names. Helm ownership checks prevent a second
release from managing the same cluster installation, even with a different
RuntimeClass name.

## Host configuration

| Value | Default |
| --- | --- |
| `containerd.config` | `/etc/containerd/config.toml` |
| `containerd.socket` | `/run/containerd/containerd.sock` |
| `containerd.service` | `containerd` |
| `installDir` | `/opt/gvisor` |

Paths are absolute host paths. The service must directly invoke the selected
containerd executable with arguments matching the live process. After the first
activation, the target identity is recorded. Changing these values or the
service invocation requires manual intervention, rather than silently
retargeting an existing installation.

`runscConfig` contains shim TOML configuration. For example:

```yaml
runscConfig: |
  [runsc_config]
    platform = "systrap"
```

Option values under `runsc_config` are strings. The installer pins `binary_name`
to the installed release. A configuration change rolls out new installer pods.

Payloads are kept under `INSTALL_DIR/releases`, with immutable shim
configurations under `INSTALL_DIR/runsc-configs`. Old generations remain for
running sandboxes and rollback. They are not garbage-collected automatically.
No binaries are downloaded on the node.

The journal is fixed at `/var/lib/gvisor-installer/state.json`. All instances
share the lifetime host lock `/run/gvisor-installer.lock`. The installer records
an activation before changing the managed configuration block. On failure or
restart, it completes the activation or restores the preceding managed block
without replacing unrelated containerd settings. Repeated failed restarts are
rate-limited across installer pod restarts. If containerd is down and the
installer process has stopped, Kubernetes cannot start a replacement installer
pod. Restore a working host configuration before resuming the rollout.

## Upgrade and removal

Drain nodes before an installation or upgrade if the workload cannot tolerate
containerd restarting. The DaemonSet permits one unavailable installer at a
time. This limits its rollout, not all possible application disruption.

Upgrade the Helm release to a matching chart and image. `helm rollback` selects
the previous desired installation. Run `kubectl rollout status` afterward,
including when using Helm 3. Keep previous images available for rollback.

`helm uninstall` removes Kubernetes resources and stops management. Host files,
the containerd handler, recovery state and node labels remain. There are no
uninstall hooks.

To remove the host installation, first stop management and drain all workloads
that use it. Back up the current containerd configuration and inspect the
journal. Remove only the block between `# BEGIN gvisor-managed` and
`# END gvisor-managed`, then validate the configuration and restart the selected
containerd service. Do not restore `containerd-original.toml` over a configuration
that may have changed since installation. After confirming that no remaining
process uses an installed generation, remove its payloads, shim configurations
and `/var/lib/gvisor-installer`. Remove the `gvisor.dev/ready` and
`gvisor.dev/version` node labels. Do not remove the lock file while an installer
process may still hold it.

## Validation

Chart rendering checks require Python 3, PyYAML and Helm:

```sh
python3 tools/gvisor_k8s_tool/helm/chart_test.py
```

The integration harness creates a disposable kind cluster and runs real gVisor
workloads. Supply a second image archive with a different complete release
payload to test upgrade and rollback:

```sh
TEST_FAILED_ACTIVATION=true \
  test/kubernetes/scripts/run_installer_e2e.sh installer-A.tar installer-B.tar
```

It also checks an ordinary workload, opt-out and reinstall. `KEEP_CLUSTER=true`
retains the cluster for diagnosis. The test prints the location of its logs.
Host-specific compatibility still needs validation on each intended node image.
