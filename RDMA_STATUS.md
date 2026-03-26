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

## Current Status (March 26, 2026)

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
  to 128MB completed successfully. Uses `NET/IB/0` (no GDRDMA). This is the
  full RDMA data path exercised through gVisor's rdmaproxy — rdma-core opens
  uverbs devices, creates PD/CQ/QP, registers MRs (with page mirroring), posts
  send/recv work requests, and polls completions.

### Not working

**NCCL `all_reduce_perf` with `NCCL_NET_GDR_LEVEL=3` (GPUDirect RDMA over IB
transport)**

NCCL fails (no longer hangs) with `Cuda failure 1 'invalid argument'` at
`transport/net.cc:961` during GDRDMA channel setup. The failure occurs in
NCCL's proxy service thread when making CUDA API calls to set up GPU-direct
buffers. The rdmaproxy itself works fine — all ioctls succeed, no rdmaproxy
errors in sentry logs.

**Root cause:** nvproxy does not fully support the CUDA calls NCCL's GDRDMA
path makes from its proxy thread. The same test works perfectly on the host
(~26 GB/s peak bandwidth), confirming this is a gVisor/nvproxy issue, not a
hardware or NCCL configuration problem.

**Additional finding:** This host has mixed link types (mlx5_0 is RoCE,
mlx5_1-8 are IB). NCCL fails if both are used. Workaround: set
`NCCL_IB_HCA=mlx5_1` to restrict to IB-only NICs.

### Next steps

1. **Diagnose the GDRDMA CUDA failure** — identify which CUDA API call fails in
   NCCL's proxy thread under nvproxy. Run with `NCCL_DEBUG=TRACE` or `NCCL_DEBUG_SUBSYS=NET`
   to get the specific call. Likely candidates: `cuMemGetAddressRange`,
   `cuPointerGetAttribute`, `cuCtxSetCurrent` in proxy thread, or DMA-BUF related.
   Note: `NCCL_IB_USE_DMABUF=0` did NOT fix the issue, so it's not DMA-BUF specific.
2. **Multi-node NCCL** between two nodes (CPU-staged IB already works; can test
   multi-node without GDRDMA)
3. **`ibv_get_async_event`** — fix or suppress the async event polling warning
   (non-blocking, NCCL continues past it)
4. **NVProxy integration for RDMA NIC isolation** — lower priority, multi-tenant
   NIC isolation

### Test results summary (March 26, 2026)

| Test | Transport | GDR | Result | Bandwidth |
|------|-----------|-----|--------|-----------|
| NCCL all_reduce (gVisor) | IB (mlx5_1) | Off (GDR_LEVEL=0) | **PASS** | ~8 GB/s |
| NCCL all_reduce (gVisor) | IB (mlx5_1) | On (GDR_LEVEL=3) | **FAIL** — CUDA error | — |
| NCCL all_reduce (gVisor) | IB (all HCAs) | On (GDR_LEVEL=3) | **FAIL** — mixed link type | — |
| NCCL all_reduce (host) | IB (mlx5_1) | On (GDR_LEVEL=3) | **PASS** | ~26 GB/s |
| NCCL all_reduce (gVisor) | TCP/Socket | Off (GDR_LEVEL=0) | **PASS** | ~0.045 GB/s |

### Open questions

- How do we quickly test RDMA support upstream? Need both mock tests (sample
  ioctl input) and hardware tests (2x8 H100 nodes running `ib_write_bw`).
- Which specific nvproxy CUDA ioctl is failing during NCCL's GDRDMA setup?

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

### Test commands

**mr_test** (MR registration pipeline):
```bash
sudo docker run --runtime=runsc-rdma --rm --network=host \
  --device=/dev/infiniband/uverbs0 mr-test
```

**cq_qp_test** (PD → MR → CQ → QP → QP INIT → teardown):
```bash
sudo docker build -f Dockerfile.cqqptest -t cqqp-test .
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm $DEVS cqqp-test cq_qp_test
```

**gdr_test** (GPUDirect RDMA — GPU MR + CPU MR + CUDA):
```bash
sudo docker build -f Dockerfile.gdrtest -t gdr-test .
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 gdr-test gdr_test
```

**nccl all-reduce over IB (CPU-staged, working):**
```bash
sudo docker build -f Dockerfile.nccl -t nccl-test .
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g \
  -e NCCL_DEBUG=INFO -e NCCL_P2P_DISABLE=1 -e NCCL_SHM_DISABLE=1 \
  -e NCCL_NET_GDR_LEVEL=0 -e NCCL_IB_HCA=mlx5_1 \
  nccl-test all_reduce_perf -b 8 -e 128M -f 2 -g 2
```

**nccl all-reduce over IB with GDRDMA (not yet working):**
```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g \
  -e NCCL_DEBUG=INFO -e NCCL_P2P_DISABLE=1 -e NCCL_SHM_DISABLE=1 \
  -e NCCL_NET_GDR_LEVEL=3 -e NCCL_IB_HCA=mlx5_1 \
  nccl-test all_reduce_perf -b 8 -e 128M -f 2 -g 2
```

**Note:** On hosts with mixed RoCE/IB link types, use `NCCL_IB_HCA=mlx5_1` (or
another IB device) to avoid `Remote RoCE device is incompatible with the local IB`
errors. `--shm-size=1g` is required (Docker default 64MB is too small for NCCL
proxy shared memory buffers).

### Log inspection

```bash
BOOTLOG=$(ls -t /tmp/runsc-rdma/logs/ | grep boot | head -1)
grep 'rdmaproxy' /tmp/runsc-rdma/logs/$BOOTLOG
```

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
