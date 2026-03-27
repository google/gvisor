# RDMA Proxy — Code Reference

Reference material for developing the rdmaproxy. Covers the existing rdmaproxy
code, nvproxy as an architectural model, and the shared memory-mapping pattern
both use.

---

## Shared Pattern: Sandbox → Sentry Page Mirroring

Both nvproxy and rdmaproxy solve the same fundamental problem: the host kernel
driver calls `pin_user_pages(addr)` which walks the **sentry process's** page
tables, but `addr` comes from the **sandbox's** address space. The sentry must
create a contiguous mapping of the same physical pages in its own VA space.

### The algorithm (identical in both proxies)

```
1. Pin:       mm.Pin(appAddrRange)  →  []PinnedRange
2. Fast path: len(prs)==1 && MapInternal gives 1 block  →  use that addr directly
3. Slow path: mmap(MAP_ANONYMOUS, PROT_NONE, len)  →  reserve contiguous VA
              for each PinnedRange:
                  MapInternal  →  get sentry kernel addr
                  mremap(MREMAP_FIXED)  →  stitch into reserved region
4. Pre-fault: madvise(MADV_POPULATE_WRITE)  →  avoid mmap_lock contention
5. Rewrite:   replace sandbox VA with sentry VA in the ioctl params
6. Forward:   ioctl(hostFD, cmd, rewritten_params)
7. Track:     store {PinnedRanges, optional owned mmap} keyed by handle
8. Cleanup:   on object destroy or fd close: munmap + mm.Unpin
```

### nvproxy implementation

`rmAllocOSDescriptor` in `pkg/sentry/devices/nvproxy/frontend.go:546-693`:
- Pins app pages, mirrors into sentry VA, rewrites `PMemory` field
- On success, transfers ownership to `osDescMem` object (`object.go:411-440`)
- `osDescMem.Release()` does munmap + Unpin
- Uses nvproxy's object tracking system (`objAdd` with handles)

### rdmaproxy implementation

`mirrorSandboxPages` in `pkg/sentry/devices/rdmaproxy/rdmaproxy_ioctl_unsafe.go:582-670`:
- Same Pin → MapInternal → mremap pattern as nvproxy
- Additional fallback tiers for GPU memory (see below)
- Ownership stored in `mirroredPages` struct (`rdmaproxy.go:111-127`)
- Tracked in `uverbsFD.pinnedMRs` / `pinnedCQs` / `pinnedQPs` maps by handle

### Three-tier fallback (rdmaproxy-specific)

rdmaproxy extends the base pattern with two fallbacks for GPU memory:

1. **`mm.Pin` succeeds** (CPU memory) → standard mirror
2. **`mm.Pin` fails** → `mirrorProxyDevicePages` (`rdmaproxy_ioctl_unsafe.go:675-712`):
   uses `InternalMappingsForRange` which resolves proxy-device-backed pages
   (GPU/UVM managed memory that has a VMA but can't be pinned normally)
3. **Both fail** (GPU device memory from `cuMemAlloc`, no CPU VMA) →
   pass VA through unmirrored; host nvidia-peermem resolves it via the NVIDIA
   driver's internal tables. Works because the sentry holds the driver context.

---

## rdmaproxy Code Map

### Files

| File | Lines | Role |
|---|---|---|
| `rdmaproxy.go` | ~240 | Device struct, Open (dev gofer), uverbsFD struct, mirroredPages/pinnedDMABufs types, Release, Register |
| `rdmaproxy_ioctl_unsafe.go` | ~1175 | All ioctl/read/write handling, page mirroring, ConfigureMMap, Translate |
| `seccomp_filter.go` | ~60 | Seccomp BPF rules for RDMA syscalls |

### Key types

```go
// rdmaproxy.go
type uverbsDevice struct { devName string }
type uverbsFD struct {
    hostFD     int32
    memmapFile fsutil.MmapNoInternalFile
    pinnedMRs  map[uint32]*mirroredPages   // keyed by MR handle
    pinnedCQs  map[uint32]*pinnedDMABufs   // keyed by CQ handle
    pinnedQPs  map[uint32]*pinnedDMABufs   // keyed by QP handle
}
type mirroredPages struct {
    prs []mm.PinnedRange
    m   uintptr  // owned sentry mmap (0 if using MapInternal directly)
    len uintptr
}
type pinnedDMABufs struct { buf, db *mirroredPages }
```

### Ioctl flow (`handleRDMAVerbsIoctl`, line 192-407)

```
1. CopyIn ioctl header (ib_uverbs_ioctl_hdr) from sandbox
2. CopyIn full attr buffer
3. Walk attrs: for each attr with data that looks like a sandbox pointer,
   CopyIn the pointed-to data into a sentry buffer, record rewrite
4. classifyIoctl → determine if this is MR_REG, CQ_CREATE, QP_CREATE, etc.
5. If MR_REG: mirrorSandboxPages, rewrite start addr
   If CQ/QP_CREATE: mirror buf_addr + db_addr from driver attr 0x1000
6. Rebuild attr buffer with rewritten pointers
7. ioctlInHostNetns(hostFD, cmd, buf) — may setns to host netns for RoCE
8. Walk attrs again: CopyOut response data back to sandbox
9. Track pinned pages by handle (MR, CQ, QP maps)
   Or release pinned pages for destroy operations
```

### Host netns handling (`ioctlInHostNetns`, line 42-64)

RoCE GID resolution requires the thread be in the host network namespace.
`ioctlInHostNetns` does `setns(hostNetnsFD, CLONE_NEWNET)` before the ioctl
and `setns(containerNetnsFD, CLONE_NEWNET)` after. Both FDs are captured at
boot before seccomp locks down.

### ConfigureMMap / Translate (lines 1155-1175)

Direct delegation to `GenericProxyDeviceConfigureMMap` — identical pattern to
nvproxy. `Translate` maps requested ranges 1:1 to the `memmapFile` backed by
`hostFD`. No offset translation needed for uverbs (unlike nvidia which
requires `vm_pgoff == 0`).

### Legacy write()/read() path (lines 868-1152)

Older rdma-core versions use `write(fd, cmd_buf)` instead of
`RDMA_VERBS_IOCTL`. The `Write` method parses the legacy command header,
applies the same page mirroring for MR REG / CQ CREATE / QP CREATE, then
`write(hostFD, buf)`. `Read` is a direct proxy.

---

## nvproxy Code Map (for reference)

### Ioctl dispatch pattern

```go
// frontend.go:210-255
func (fd *frontendFD) Ioctl(...) {
    nr := linux.IOC_NR(cmd)
    fi := frontendIoctlState{fd, ctx, t, nr, argPtr, argSize}
    result, err := fd.dev.nvp.abi.frontendIoctl[nr].handle(&fi)
}
```

nvproxy dispatches by `IOC_NR` to a **registered handler table** (`abi.frontendIoctl`).
Each handler: CopyIn params → rewrite sandbox FDs/pointers → `frontendIoctlInvoke`
(raw ioctl to hostFD) → CopyOut. Handlers are registered with capability flags.

rdmaproxy uses a single generic handler (`handleRDMAVerbsIoctl`) because the
RDMA ioctl interface is self-describing (header + typed attrs). nvproxy needs
per-ioctl handlers because each nvidia ioctl has a different struct layout.

### Host ioctl invocation

```go
// frontend_unsafe.go:38-43
func frontendIoctlInvokeNoStatus[Params any](fi, ioctlParams) {
    unix.RawSyscall(unix.SYS_IOCTL, uintptr(fi.fd.hostFD), cmd, ptr)
}
```

rdmaproxy equivalent: `ioctlInHostNetns` wraps the raw ioctl with netns
switching (nvproxy doesn't need this — GPU ioctls aren't netns-sensitive).

### ConfigureMMap

```go
// frontend_mmap.go:31-48
func (fd *frontendFD) ConfigureMMap(...) error {
    return vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, fd, opts)
}
func (fd *frontendFD) Translate(...) {
    return []memmap.Translation{{Source: optional, File: &fd.memmapFile,
        Offset: optional.Start, Perms: hostarch.AnyAccess}}, nil
}
```

rdmaproxy's implementation is byte-for-byte identical.

### MapInternal (backing host mmap)

```go
// frontend_mmap_unsafe.go:29-65
func (mf *frontendFDMemmapFile) MapInternal(fr, at) {
    // Lazily mmap(MAP_SHARED, hostFD) the full region on first access
    // Then slice into it for the requested FileRange
}
```

rdmaproxy uses `fsutil.MmapNoInternalFile` which delegates to the VFS
infrastructure rather than managing its own mmap. The effect is the same.

### Object lifecycle

nvproxy has a rich object tracking system (`rootClient.resources` map, typed
object impls). rdmaproxy uses simpler per-FD maps (`pinnedMRs`, `pinnedCQs`,
`pinnedQPs`) since RDMA objects don't form hierarchies the way RM objects do.

---

## Integration points (outside rdmaproxy package)

| File | What it does |
|---|---|
| `runsc/boot/vfs.go` ~1515, ~1596 | `rdmaproxy.Register()` — registers uverbs devices |
| `runsc/boot/loader.go` ~516 | `rdmaproxy.SetHostNetnsFD(args.HostNetnsFD)` |
| `runsc/boot/filter/config/config.go` ~165 | `s.Merge(rdmaproxy.Filters())` — seccomp rules |
| `runsc/cmd/gofer.go` ~669-673 | Bind-mount `/dev/infiniband/` into gofer FS |
| `runsc/config/flags.go` ~167-168 | `--rdmaproxy`, `--rdma-expected-ipoib` flags |
| `runsc/config/config.go` ~355+ | `RDMAProxy` config field |
| `runsc/specutils/specutils.go` ~666-668 | `RDMAProxyIsEnabled()` helper |
| `runsc/container/container.go` ~1272 | Creates dev gofer when RDMA proxy enabled |
| `pkg/sentry/fsimpl/sys/rdma.go` | Virtual sysfs for infiniband device discovery |
| `runsc/cmd/chroot.go` | Collects host sysfs data before pivot_root |
| `runsc/cmd/boot.go` | Deserializes sysfs data in sentry boot path |

---

## Multi-node NCCL Notes

### Current observed behavior (March 27, 2026)

Multi-node NCCL over RDMA is now **functionally working** in gVisor across two
8xH200 nodes:

- NCCL initializes with `nNodes 2`
- Inter-node channels use `NET/IB/.../GDRDMA`
- `runsc-rdma` boot logs show `nvidia_peermem` detection and RDMA sysfs
  collection on both nodes
- The workload exits successfully

However, throughput is still dramatically below the matching host and `runc`
baselines:

- extracted host binary: ~308 GB/s bus bandwidth at 128 MiB
- `docker --runtime=runc`: ~307 GB/s
- `docker --runtime=runsc-rdma`: ~10.8 GB/s

So the current state is: **correctness yes, performance no**.

### Practical launch notes

On the validated Crusoe H200 pair, these HCAs were management devices and
should not be used for the NCCL data path:

- `mlx5_1`
- `mlx5_2`
- `mlx5_7`
- `mlx5_8`

The working HCA allowlist was:

```bash
NCCL_IB_HCA=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11
```

Bootstrap/OOB traffic used:

```bash
NCCL_SOCKET_IFNAME=eth0
```

For gVisor multi-node runs, `NCCL_DMABUF_ENABLE=0` is still required so NCCL
uses the nvidia-peermem path instead of the unsupported DMA-BUF path.

### Most likely debugging area

Because the gVisor run still shows `NET/IB/.../GDRDMA`, this does **not** look
like a simple "fell back to sockets" or "fell back to CPU-staged RDMA" bug.
The first places to inspect are:

1. Extra overhead in the RDMA ioctl path during steady-state communication
2. mmap/doorbell/CQ/QP behavior that preserves correctness but harms latency
3. Interaction between nvproxy and rdmaproxy in multi-node GDRDMA mode
4. Any thread scheduling or proxy-service behavior unique to `runsc-rdma`
