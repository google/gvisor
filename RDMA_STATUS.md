# RDMA Proxy — Project Context & Status

This is a **living document** — update it as progress is made.

For code-level reference (function signatures, nvproxy patterns, integration
points), see `RDMA_REFERENCE.md`.

**Author:** @Alessio Toniolo | **Reviewers:** @Peyton

## Goal

Get RDMA working inside of gVisor to support multi-node GPU workloads.

**Motivation:** Multi-node containers currently assume ownership of the entire
host. gVisor isolation would allow multiple containers to share a host while
still accessing RDMA hardware. We modify gVisor's internals to accommodate
applications that bypass the kernel for IB verbs.

**Platform choice:** systrap (not KVM or ptrace). systrap marks syscalls with
`SIGSYS` and communicates via stub threads to the Sentry. It supports GPU
workloads in both bare metal and nested virtualization environments.

---

## Current Status (March 27, 2026)

### Working end-to-end

- `ibv_devinfo`, `ibv_devices` — device discovery via virtual sysfs
- `ib_write_bw` / `ib_read_bw` with `--network=host`
- All core uverbs operations: ALLOC_PD, ALLOC_CONTEXT, CREATE_CQ, CREATE_QP,
  REG_MR, DEREG_MR, DESTROY_*, QUERY_PORT, QUERY_GID
- mmap of doorbell pages, CQ/QP buffers, UAR pages
- GPUDirect RDMA via nvidia-peermem (MR REG of GPU memory)
- NCCL `all_reduce_perf` with `NCCL_NET_GDR_LEVEL=0` (TCP/Socket transport) —
  EXIT=0
- **NCCL `all_reduce_perf` over IB transport (GDR_LEVEL=0, CPU-staged RDMA)** —
  EXIT=0, ~8 GB/s peak bus bandwidth, 384 MR registrations, all data sizes 8B
  to 128MB completed successfully. Uses `NET/IB/0` (no GDRDMA).
- **NCCL `all_reduce_perf` over IB with GDRDMA (GDR_LEVEL=3, peermem path)** —
  EXIT=0, **~25 GB/s peak bus bandwidth** (2 GPUs on mlx5_1), all data sizes 8B
  to 128MB completed. Uses `NET/IB/0/GDRDMA`. Requires `NCCL_DMABUF_ENABLE=0`
  to bypass DMA-BUF (which nvproxy doesn't fully support) and use the
  nvidia-peermem path. Virtual sysfs exposes
  `/sys/module/nvidia_peermem/version` and
  `/sys/kernel/mm/memory_peers/nv_mem/version` so NCCL's `ncclIbGdrSupport()`
  detects peermem. 8-GPU test also works with GDRDMA across all 8 IB NICs
  (mlx5_1-8), but throughput is CPU-limited (~2.5 GB/s bus BW) due to this
  instance having only 5 vCPUs.
- **Multi-node NCCL all-reduce over RDMA now works end-to-end in gVisor** —
  two 8xH200 nodes successfully completed `nccl_multinode_bench` with
  `NRANKS=2`, `NGPUS=8`, `NCCL_NET_GDR_LEVEL=3`, and
  `NCCL_DMABUF_ENABLE=0`. NCCL reports `nNodes 2` and `NET/IB/.../GDRDMA` on
  inter-node channels, and gVisor boot logs show `nvidia_peermem` detection and
  RDMA sysfs collection on both nodes.

### Not yet working

- **DMA-BUF path for GDRDMA** — `cuMemGetHandleForAddressRange` fails in
  nvproxy (CUDA rejects in user-space before reaching the kernel). Workaround:
  `NCCL_DMABUF_ENABLE=0` forces the nvidia-peermem path which has equivalent
  performance.
- **Multi-node GDRDMA performance in gVisor is severely underperforming** —
  on two 8xH200 nodes, the matching extracted-host and `runc` baselines reach
  ~308 GB/s bus bandwidth at 128 MiB, but `runsc-rdma` reaches only
  ~10.8 GB/s at the same size despite still using `NET/IB/.../GDRDMA`. This is
  now a correctness-complete but performance-blocking issue.

**Mixed link types:** This host has mixed link types (mlx5_0 is RoCE,
mlx5_1-8 are IB). NCCL fails if both are used. Workaround: set
`NCCL_IB_HCA=^mlx5_0` to exclude the RoCE device.

**Crusoe H200 HCA layout:** On the two H200 nodes used for validation,
`mlx5_1`, `mlx5_2`, `mlx5_7`, and `mlx5_8` are management devices and should be
excluded from the data path. The working allowlist was
`mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11`.

### Next steps

1. **Investigate multi-node gVisor performance collapse** — correctness is now
   there, but throughput drops from ~308 GB/s (`runc`) to ~10.8 GB/s
   (`runsc-rdma`) on the same 2-node, 8-GPU-per-node workload
2. **Fix DMA-BUF support in nvproxy** — make `cuMemGetHandleForAddressRange`
   work so `NCCL_DMABUF_ENABLE=0` isn't needed (lower priority since peermem
   path has equivalent performance)
3. **`ibv_get_async_event`** — fix or suppress the warning
4. **NVProxy integration for RDMA NIC isolation** — multi-tenant

### Test results summary (March 27, 2026)

| Test | Transport | GDR | Result | Peak Bus BW |
|------|-----------|-----|--------|-------------|
| NCCL all_reduce (gVisor, 2 GPU) | IB (mlx5_1) | On (GDR_LEVEL=3, peermem) | **PASS** | **~25 GB/s** |
| NCCL all_reduce (host/runc, 2 GPU) | IB (mlx5_1) | On (GDR_LEVEL=3) | **PASS** | ~26 GB/s |
| NCCL all_reduce (gVisor, 8 GPU) | IB (all IB HCAs) | On (GDR_LEVEL=3, peermem) | **PASS** | ~5 GB/s * |
| NCCL all_reduce (host/runc, 8 GPU) | IB (all IB HCAs) | On (GDR_LEVEL=3) | **PASS** | ~6 GB/s * |
| NCCL all_reduce (gVisor, 2 GPU) | IB (mlx5_1) | Off (GDR_LEVEL=0) | **PASS** | ~8 GB/s |
| NCCL all_reduce (gVisor) | TCP/Socket | Off (GDR_LEVEL=0) | **PASS** | ~0.045 GB/s |
| NCCL multinode bench (host extracted binary, 2x8 GPU) | IB (explicit HCA allowlist) | On (GDR_LEVEL=3) | **PASS** | **~307.99 GB/s** |
| NCCL multinode bench (`runc`, 2x8 GPU) | IB (explicit HCA allowlist) | On (GDR_LEVEL=3, peermem forced) | **PASS** | **~306.69 GB/s** |
| NCCL multinode bench (`runsc-rdma`, 2x8 GPU) | IB (explicit HCA allowlist) | On (GDR_LEVEL=3, peermem forced) | **PASS** | **~10.78 GB/s** |

\* 8-GPU results limited by Docker daemon cpuset (5 vCPUs). Both gVisor and
host/runc show the same bottleneck — not a gVisor issue. With sufficient CPUs
(>=16 for 8 GPUs), expect near-linear scaling from the 2-GPU result.

Per-link IB bandwidth: **400 Gb/s NDR (50 GB/s)** per NIC (mlx5_1-8).

### Open questions

- How do we quickly test RDMA support upstream? Need both mock tests (sample
  ioctl input) and hardware tests (2x8 H100 nodes running `ib_write_bw`).
- Will DMA-BUF eventually be needed for multi-node GDRDMA, or is peermem
  sufficient long-term?
- Why does multi-node GDRDMA preserve functional `NET/IB/.../GDRDMA` operation
  in gVisor while losing ~30x throughput relative to the matching `runc`
  container baseline?

For full build/test/run instructions, see `TEST.md`.

---

## Implementation Map

### RDMA proxy files

| Component | Files |
|---|---|
| **Virtual sysfs** | `pkg/sentry/fsimpl/sys/rdma.go` (data structures, sysfs construction), `runsc/cmd/chroot.go` (host data collection), `runsc/cmd/boot.go` (deserialization) |
| **uverbs device proxy** | `pkg/sentry/devices/rdmaproxy/rdmaproxy.go` (registration, Open, polling), `runsc/boot/vfs.go` (pre-registration), `runsc/container/container.go` (dev gofer creation), `runsc/cmd/gofer.go` (bind-mounts) |
| **ioctl proxy** | `pkg/sentry/devices/rdmaproxy/rdmaproxy_ioctl_unsafe.go` (generic ioctl handler + page mirroring + mmap proxy) |
| **Seccomp filters** | `pkg/sentry/devices/rdmaproxy/seccomp_filter.go`, `runsc/boot/filter/config/config.go` |

### What each component does

1. **Virtual sysfs for RDMA device discovery** —
   `/sys/class/infiniband_verbs/` and `/sys/class/infiniband/` populated from
   host data collected at container startup. Serialized to JSON in chroot,
   deserialized by sentry. Sysfs `dev` files report the container's dynamic
   major:minor so libibverbs can match against `/dev` nodes.

2. **uverbs device proxy** — `/dev/infiniband/uverbs*` chardevs registered with
   dynamic VFS majors. Open uses the **dev gofer** (helper process outside
   chroot) to obtain a host FD, matching nvproxy/tpuproxy pattern.

3. **ioctl proxy** — The modern `_IOWR(0x1b, 1, ...)` ioctl uses a
   self-describing `ib_uverbs_ioctl_hdr` + variable-length `ib_uverbs_attr[]`
   array. Handler parses header, walks attrs, copies sandbox-pointer-backed data
   into sentry buffers, rewrites pointers, forwards to host kernel, copies
   results back. Also handles legacy `write()`/`read()` command path for older
   rdma-core.

4. **Page mirroring (`mirrorSandboxPages`)** — Pins sandbox pages via
   `mm.Pin()`, maps into sentry VA via `MapInternal()` + `mremap`, rewrites
   address. Used for MR REG, CQ CREATE (buf_addr + db_addr), and QP CREATE.
   Handles tracked for cleanup on destroy/close.

5. **mmap proxy** — `ConfigureMMap` and `Translate` forward device mmaps
   (doorbell pages, CQ buffers) to host FD via
   `GenericProxyDeviceConfigureMMap`.

6. **Seccomp filters** — Allows `ioctl` (magic `0x1b`), `mmap` (MAP_SHARED on
   device FDs), `munmap`, `openat`, `write`, `read` when `--rdmaproxy` is
   enabled.

7. **Runtime flags** — `--rdmaproxy` enables the proxy;
   `--rdma-expected-ipoib=N` controls IPoIB interface waiting (`-1` to disable
   on RoCE-only machines).

---

## Key Technical Concepts

### Page mirroring for MR registration

`ibv_reg_mr()` tells the kernel to pin physical pages for NIC DMA. The kernel's
`pin_user_pages(addr)` walks the **calling process's page tables**. Our proxy
forwards from the sentry, but the VA refers to the sandbox's address space — so
pages aren't found.

**Fix:** `mirrorSandboxPages()` resolves sandbox VA to physical pages via
`mm.Pin()`, maps them into sentry VA via `MapInternal()` + `mremap`, and
rewrites the `start` field. The `hca_va` (used for RDMA addressing, not page
pinning) is preserved so remote peers can use the sandbox VA in work requests.

### Three-tier memory resolution for MR REG

1. **CPU memory** (malloc): `mm.Pin` succeeds → mirror into sentry → rewrite
   `start`
2. **GPU memory with VMA** (cuMemAllocManaged): `mm.Pin` fails →
   `InternalMappingsForRange` resolves proxy device pages → mirror → rewrite
3. **GPU device memory** (cuMemAlloc): both fail → pass GPU VA through
   unmirrored → host `pin_user_pages` fails → **nvidia-peermem** intercepts →
   resolves via NVIDIA driver internals → returns physical GPU pages to IB
   subsystem

The passthrough works because the sentry holds the NVIDIA driver context
(nvproxy forwards all GPU ioctls from the sentry process).

### CQ/QP DMA buffer mirroring

CQ CREATE and QP CREATE pass `buf_addr` + `db_addr` to the host via mlx5 driver
attrs (id=0x1000). Same `mirrorSandboxPages` pattern. CREATE vs DESTROY detected
by presence of driver input attr `0x1000` (not method IDs, which vary across
kernel versions).

### Namespace constraints (why `--network=host` is required for RoCE)

The sandbox always runs in a **user namespace**. `ibv_modify_qp` (INIT→RTR)
checks `net_eq(dev_net(gid_ndev), gid_attr->net)` — the GID's physical NIC must
be in the caller's netns. With bridge networking, the sentry is in a container
netns where the physical NIC is absent → ENODEV.

`setns(CLONE_NEWNET)` requires `CAP_SYS_ADMIN` in the init user namespace,
which child userns cannot grant. Link endpoints can't fix it either — kernel
checks exact `struct net_device *` pointer identity.

---

## Runtime Configuration

### daemon.json (Docker runtime registration)

```json
{
  "runtimes": {
    "runsc-rdma": {
      "path": "/usr/local/bin/runsc-rdma",
      "runtimeArgs": [
        "--debug",
        "--debug-log=/tmp/runsc-rdma/logs/",
        "--rdmaproxy",
        "--nvproxy",
        "--network=host",
        "--rdma-expected-ipoib=-1"
      ]
    }
  }
}
```

Docker's `--network=host` and gVisor's `--network=host` are **separate flags**.
Docker's skips the network namespace; gVisor still defaults to netstack
(`--network=sandbox`). Without `--network=host` in runsc args, gVisor uses
netstack → zero interfaces → `getifaddrs()` returns empty → NCCL bootstrap
fails.

---

## Testing

See `TEST.md` for complete build, deploy, and test instructions.

---

## Reference: Host Device Layout

### Character devices (`/dev/infiniband/`)

- `uverbs0`–`uverbs8` — major 231, minors 192–200 (mode 0666)
- `umad0`–`umad8` — major 231, minors 0–8
- `rdma_cm` — major 10, minor 121 (misc device)

### Sysfs (required for libibverbs discovery)

- `/sys/class/infiniband_verbs/uverbsN/` — `ibdev`, `abi_version`, `dev`,
  `device` symlink
- `/sys/class/infiniband/mlx5_N/` — `node_type`, `node_guid`,
  `sys_image_guid`, `fw_ver`, `hca_type`, `hw_rev`, `board_id`, `node_desc`
- `/sys/class/infiniband/mlx5_N/ports/1/` — `state`, `phys_state`,
  `link_layer`, `rate`, `lid`, `sm_lid`, `sm_sl`, `cap_mask`, `gids/`,
  `pkeys/`, `gid_attrs/`, `counters/`, `hw_counters/`

### libibverbs discovery flow

1. `socket(AF_NETLINK, SOCK_RAW, NETLINK_RDMA)` → `EPROTONOSUPPORT` (expected)
2. `openat("/sys/class/infiniband_verbs")` → virtual sysfs
3. Read `ibdev`, `abi_version`, `dev` for each uverbsN → dev patched to dynamic
   major
4. `stat("/dev/infiniband/uverbsN")` matches `st_rdev` against sysfs `dev` →
   DynMajor
5. `open("/dev/infiniband/uverbsN")` → dev gofer
6. `RDMA_VERBS_IOCTL` (CAPABILITY_PROBE, QUERY_GID, ALLOC_CONTEXT,
   QUERY_PORT, ...) → probe-based ioctl proxy

### Note on IPoIB vs RoCE

Some providers have IPoIB interfaces; others (e.g. OCI) only have Ethernet
interfaces with RoCE. Use `--rdma-expected-ipoib=-1` on RoCE-only machines.
