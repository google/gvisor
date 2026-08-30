# Run DeepSeek Harness commands with gVisor

This guide shows how to route selected DeepSeek Harness commands through Docker
and `runsc` for execution inside a gVisor sandbox.

This is an invocation-path integration, not a native DeepSeek Harness sandbox
plugin. Commands use gVisor only when explicitly routed through the launcher described
below.

This execution path is:

```text
DeepSeek Harness
  tool admission, approval, workspace policy
        |
        | explicit routing
        v
workspace-local launcher
        |
        v
Docker / OCI
  mounts, network, identity, capabilities, lifecycle
        |
        v
runsc / gVisor
  application-kernel isolation
```

Using `runsc` does not move Harness approval, permission, workspace, or network
policy into gVisor. Each layer remains responsible for its own boundary.

## Tested environment

The following is the validation baseline, not a set of minimum supported
versions:

| Component                 | Tested version                                                                   |
| ------------------------- | -------------------------------------------------------------------------------- |
| DeepSeek Harness revision | `cd5ef8148158c3a752a658978873241fdf8e2bbc`                                       |
| Harness profile           | `headless`                                                                       |
| Permission preset         | `workspace-write` (`workspace-write` + `ask`)                                    |
| gVisor revision           | `4a7fcd5fc0489e76ee736b16c956c97ba641fe6b`                                       |
| runsc                     | `release-20260803.0-258-g4a7fcd5fc048`                                           |
| runsc OCI spec            | `1.2.1`                                                                          |
| Docker                    | `29.7.2`                                                                         |
| Host                      | Ubuntu 22.04.5 LTS, Linux `6.8.0-138-generic`, `x86_64`                          |
| Image                     | `ubuntu:24.04`                                                                   |
| Image digest              | `ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517` |

The commands below use the standard Docker runtime name `runsc`.

## Prerequisites

Install DeepSeek Harness and configure a model provider.

Install gVisor and register `runsc` with Docker as described in the
[Docker Quick Start](../quick_start/docker.md). For production deployments,
also review the [Production guide](../production.md).

Verify that Docker can start a gVisor container:

```bash
docker run --rm --runtime=runsc ubuntu:24.04 dmesg | head -1
```

The output should begin with:

```text
[    0.000000] Starting gVisor...
```

This is only a functional runtime check, not a security attestation.

## Create a workspace-local launcher

From the directory that will be used as the Harness workspace:

```bash
mkdir -p .gvisor
cat > .gvisor/run-gvisor <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

RUNTIME="${GVISOR_RUNTIME:-runsc}"
IMAGE="${GVISOR_IMAGE:-ubuntu:24.04}"
WORKSPACE="${GVISOR_WORKSPACE:-$(pwd -P)}"

exec docker run \
  --rm \
  --runtime="$RUNTIME" \
  --mount "type=bind,src=$WORKSPACE,dst=/workspace" \
  --workdir /workspace \
  "$IMAGE" \
  "$@"
EOF

chmod +x .gvisor/run-gvisor
```

Test the launcher directly:

```bash
./.gvisor/run-gvisor \
  sh -c 'pwd; echo "hello from gVisor" > integration-test.txt'
```

The working directory inside the container is `/workspace`, and
`integration-test.txt` is visible in the host workspace because that directory
is explicitly bind-mounted.

This launcher is a convenience path, not an admission controller. It assumes
the Harness tool process is permitted to invoke the local Docker daemon.

## Run from DeepSeek Harness

Start Harness from the same workspace directory:

```bash
DSH_PERMISSION_MODE=workspace-write \
dsh --profile headless \
  "Use bash to run ./.gvisor/run-gvisor \
  sh -c 'echo harness-gvisor-ok > /workspace/harness-gvisor.txt'"
```

Verify the bounded workspace artifact:

```bash
cat harness-gvisor.txt
```

Expected output:

```text
harness-gvisor-ok
```

This validates the Docker-managed execution path:

```text
Harness workspace-write
  -> workspace-local launcher
  -> Docker
  -> runsc
  -> gVisor
  -> /workspace
```

Verify the resulting artifact rather than relying on the final assistant text
alone as evidence that the tool completed.

This path was tested separately with Harness's mock LLM and with a
credential-backed DeepSeek provider. The mock path verifies deterministic tool
dispatch; the credential-backed path additionally verifies the real provider
flow. Neither establishes multi-tenant isolation.

## Responsibility boundaries

The integration does not collapse all policy into gVisor.

| Concern                                            | Responsible layer                                        |
| -------------------------------------------------- | -------------------------------------------------------- |
| Tool admission and approval                        | DeepSeek Harness                                         |
| Permission preset and workspace file-effect policy | DeepSeek Harness                                         |
| OCI mounts and container lifecycle                 | Docker / OCI configuration                               |
| Container network                                  | Docker / OCI configuration                               |
| Container UID/GID                                  | Docker / OCI configuration                               |
| Capabilities, PID limit, and device exposure       | Docker / OCI configuration                               |
| Application-kernel isolation                       | runsc / gVisor                                           |
| Provider credential provisioning                   | Harness/provider configuration and container environment |

In the tested Harness revision, the `workspace-write` preset combines the
`workspace-write` file-effect mode with the `ask` approval policy. The preset
selects those policies; their enforcement remains in the corresponding Harness
services.

Harness filesystem policy and gVisor therefore enforce different boundaries.

## Harden the container

The minimal launcher leaves Docker's default network, identity, capability, and
root filesystem settings in place.

The following options reduce the privileges of containers created through the
launcher. They do not constrain a Harness tool that can invoke the Docker daemon
independently.

Replace the `exec docker run` block with:

```bash
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

exec docker run \
  --rm \
  --runtime="$RUNTIME" \
  --user="$HOST_UID:$HOST_GID" \
  --network=none \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --pids-limit=128 \
  --mount "type=bind,src=$WORKSPACE,dst=/workspace" \
  --workdir /workspace \
  "$IMAGE" \
  "$@"
```

In the tested configuration:

* the workload ran with the invoking user's UID/GID;
* `--cap-drop=ALL` produced an empty effective capability set;
* `no-new-privileges` was enabled;
* the container root filesystem was read-only;
* `/tmp` was a bounded, ephemeral tmpfs;
* `--network=none` blocked external network access;
* Docker was configured with `--pids-limit=128`;
* `/workspace` remained the persistent writable area.

Running with the invoking user's UID/GID also matters for workspace access. In
testing, container root with all capabilities dropped could not write a
workspace owned by another UID, while the matching UID/GID could.

If the workload should not modify the workspace, make the bind mount read-only:

```text
--mount "type=bind,src=$WORKSPACE,dst=/workspace,readonly"
```

## Security boundaries

### OCI workspace mount

Inside the gVisor container, the tested configuration allowed reads and writes
in the explicitly mounted workspace.

An unmounted host directory could not be read, created in, or overwritten
through its host absolute path. It also remained unreachable through `..` path
traversal and through a workspace symlink pointing to that host path.

These checks validate the tested OCI filesystem configuration, not the complete
Harness filesystem policy. They apply only to host paths that are not explicitly
supplied to Docker.

### Docker daemon access

Docker daemon access is a separate privileged boundary from Harness
`workspace-write`.

In a controlled test, a workspace-local Harness command invoked Docker and
asked it to bind-mount a host directory outside the Harness workspace. The
resulting gVisor container could modify that directory.

This is not a gVisor escape. Docker explicitly supplied the directory in the OCI
configuration, and gVisor enforced that configuration.

A shell launcher alone therefore cannot enforce a mount allowlist if the tool
can invoke Docker directly. If that boundary matters, Docker access must be
restricted or mediated by a trusted layer.

Do not expose the host Docker socket inside model-generated workloads.

### Network and credentials

The default Docker-managed `runsc` configuration allowed outbound network access
in testing. gVisor does not imply deny-egress. `--network=none` blocked the
tested outbound connection.

Do not pass provider or host credentials into the gVisor container unless the
workload requires them.

In the credential-backed test, the ambient `DEEPSEEK_API_KEY` was not observed
in the Harness bash subprocess or in the gVisor container. This does not prove
that every credential source is inaccessible to every tool.

### Devices and capabilities

The tested container was not privileged, contained no host Docker socket, and
Docker reported no explicitly passed host devices.

Sandbox device nodes such as `/dev/fuse` and `/dev/net/tun` were still visible;
their presence alone does not demonstrate host device passthrough.

Docker's default effective capability set was non-empty. With
`--cap-drop=ALL`, `CapEff` was zero. This guide does not provide an exhaustive
setuid or capability conformance test.

## Failure and cleanup semantics

At the Docker/`runsc` boundary, a non-zero process exit status reached the
caller, and stdout and stderr were preserved independently.

A command that wrote to the mounted workspace and then exited non-zero left the
completed write behind. Command failure is not transactional and does not roll
back workspace side effects.

Using `docker run --rm` removed the Docker container object after both
successful and failed commands.

Harness's session model includes `tool/call` and `tool/result` events, and the
`headless` profile persists its session. This guide did not inspect or depend on
Harness's serialized session-storage representation, so it does not claim
byte-for-byte correspondence between process stdout, stderr, or exit status and
the persisted `tool/result`.

## Scope and limitations

This guide covers the Docker-managed `runsc` path only. It does not claim
behavioral parity with direct OCI or direct `runsc` integration.

The following were not exhaustively validated:

* timeout and cancellation behavior;
* oversized tool output;
* background and child-process cleanup;
* runtime temporary-file and mount cleanup beyond Docker container removal;
* exhaustive setuid/capability behavior;
* PID-limit behavior under adversarial process creation;
* multi-tenant isolation;
* the complete Harness shell-tool execution contract.

gVisor reduces exposure of the host kernel by executing application system calls
against the gVisor application kernel. It does not replace Harness tool policy
or Docker/OCI resource policy, and using gVisor alone does not prove isolation
of every host or application resource.
