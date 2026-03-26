# RDMA Proxy — Build & Test Guide

Step-by-step instructions for building `runsc-rdma`, configuring Docker, and
running NCCL all-reduce tests with GDRDMA inside gVisor.

---

## 1. Prerequisites

### Host requirements

- Linux host with RDMA-capable NICs (mlx5) and NVIDIA GPUs
- Docker with nvidia-container-toolkit installed
- `nvidia_peermem` kernel module loaded (required for GDRDMA)

### Verify hardware

```bash
# GPUs
nvidia-smi --query-gpu=index,name --format=csv,noheader

# IB / RoCE devices
ibv_devinfo | head -40

# uverbs device nodes
ls /dev/infiniband/uverbs*
```

### Load nvidia_peermem

```bash
sudo modprobe nvidia_peermem
lsmod | grep nvidia_peermem
cat /sys/module/nvidia_peermem/version
```

If `modprobe` fails, the module may not be installed. Check
`modinfo nvidia_peermem` and install the appropriate NVIDIA driver package.

### Check available CPUs

NCCL proxy threads need CPU cores. Each GPU pair needs ~2 cores for the proxy
service and progress threads. Check how many CPUs Docker can use:

```bash
sudo docker info 2>&1 | grep CPUs
```

For 8-GPU tests, you want at least 16 CPUs. If Docker reports fewer (e.g. 5),
the 8-GPU test will be CPU-bottlenecked — both for gVisor and host/runc. The
2-GPU test needs only ~4 CPUs and will hit line rate on any instance.

---

## 2. Build runsc-rdma

The build runs inside a Docker container via `make`. Bazel builds are cached
in a Docker volume, so incremental builds are fast.

```bash
cd ~/gvisor
sudo make copy TARGETS=runsc DESTINATION=/tmp
```

First build takes ~7 minutes. Incremental builds take ~15–30 seconds.

### Force a clean build

If you suspect Bazel is using stale cached outputs (e.g. the binary doesn't
contain your changes), clean the cache and rebuild:

```bash
sudo docker exec gvisor-bazel-$(tools/compat/realpath.py . | md5sum | cut -c1-8)-x86_64 \
  bazel clean --expunge
sudo make copy TARGETS=runsc DESTINATION=/tmp
```

### Verify the binary has your changes

```bash
strings /tmp/runsc | grep "your_unique_string"
```

---

## 3. Deploy the binary

```bash
sudo pkill -f "runsc-rdma" 2>/dev/null; sleep 1
sudo rm -f /usr/local/bin/runsc-rdma
sudo cp /tmp/runsc /usr/local/bin/runsc-rdma
sudo chmod +x /usr/local/bin/runsc-rdma
```

Verify:

```bash
ls -la /usr/local/bin/runsc-rdma
md5sum /tmp/runsc /usr/local/bin/runsc-rdma   # hashes must match
```

---

## 4. Configure Docker daemon

Register `runsc-rdma` as a Docker runtime. This only needs to be done once
(or when runtime args change).

```bash
sudo python3 -c "
import json, os
p = '/etc/docker/daemon.json'
d = json.load(open(p)) if os.path.exists(p) else {}
d.setdefault('runtimes', {})['runsc-rdma'] = {
    'path': '/usr/local/bin/runsc-rdma',
    'runtimeArgs': [
        '--debug',
        '--debug-log=/tmp/runsc-rdma/logs/',
        '--rdmaproxy',
        '--nvproxy',
        '--network=host',
        '--rdma-expected-ipoib=-1'
    ]
}
json.dump(d, open(p,'w'), indent=2)
"
sudo systemctl restart docker
sleep 2
```

Update the mirror file so other agents/scripts can see the config:

```bash
cp /etc/docker/daemon.json daemon_json_mirror.json
```

### Clear logs before each test run

```bash
sudo rm -rf /tmp/runsc-rdma/logs && sudo mkdir -p /tmp/runsc-rdma/logs
```

### Verify runtime is registered

```bash
sudo docker info 2>&1 | grep -E "Runtimes|runsc"
```

---

## 5. Build the NCCL test Docker image

```bash
cd ~/gvisor
sudo docker build -f Dockerfile.nccl -t nccl-test .
```

This builds `nccl-tests` from source inside a CUDA container. Takes ~5 minutes
on first build, cached afterwards.

---

## 6. Run NCCL all-reduce tests

All commands below use this helper to pass all uverbs devices:

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
```

### GDRDMA — 2 GPUs, single IB NIC (~25 GB/s peak)

This is the primary bandwidth test. Uses one IB NIC (mlx5_1) with GPUDirect
RDMA via nvidia-peermem. Expect ~25 GB/s peak bus bandwidth, matching host
baseline.

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=INFO \
  -e NCCL_P2P_DISABLE=1 \
  -e NCCL_SHM_DISABLE=1 \
  -e NCCL_DMABUF_ENABLE=0 \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_IB_HCA=mlx5_1 \
  nccl-test all_reduce_perf -b 8 -e 128M -f 2 -g 2
```

**What to look for:**
- `Connected all rings, use ring PXN 0 GDR 1` — GDRDMA is active
- `via NET/IB/0/GDRDMA` on channel lines — peermem path in use
- Peak bus bandwidth >=20 GB/s at 32MB+ sizes
- `Out of bounds values : 0 OK` — data correctness verified

### GDRDMA — 8 GPUs, all IB NICs

Uses all 8 IB NICs (mlx5_1-8), excludes the RoCE device (mlx5_0). Bandwidth
scales with available CPUs — needs ~16+ CPUs for full throughput.

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=INFO \
  -e NCCL_P2P_DISABLE=1 \
  -e NCCL_SHM_DISABLE=1 \
  -e NCCL_DMABUF_ENABLE=0 \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e 'NCCL_IB_HCA=^mlx5_0' \
  nccl-test all_reduce_perf -b 8 -e 128M -f 2 -g 8
```

**What to look for:**
- All 8 IB NICs used: `NET/IB : Using [0]mlx5_2 ... [7]mlx5_4`
- `GDR 1` on all ranks
- If bandwidth is low, check `sudo docker info | grep CPUs`

### CPU-staged IB (no GDRDMA, ~8 GB/s peak)

Useful as a comparison baseline. Data goes GPU → CPU → NIC instead of
GPU → NIC directly.

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=INFO \
  -e NCCL_P2P_DISABLE=1 \
  -e NCCL_SHM_DISABLE=1 \
  -e NCCL_NET_GDR_LEVEL=0 \
  -e NCCL_IB_HCA=mlx5_1 \
  nccl-test all_reduce_perf -b 8 -e 128M -f 2 -g 2
```

### Host baseline (runc, no gVisor)

Run the same test on the host Docker runtime to establish a baseline. Remove
`--runtime=runsc-rdma` to use the default runc runtime:

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=WARN \
  -e NCCL_P2P_DISABLE=1 \
  -e NCCL_SHM_DISABLE=1 \
  -e NCCL_DMABUF_ENABLE=0 \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_IB_HCA=mlx5_1 \
  nccl-test all_reduce_perf -b 8 -e 128M -f 2 -g 2
```

---

## 7. Environment variables reference

| Variable | Value | Purpose |
|---|---|---|
| `NCCL_P2P_DISABLE=1` | 1 | Disable NVLink, force IB transport |
| `NCCL_SHM_DISABLE=1` | 1 | Disable shared memory, force IB transport |
| `NCCL_DMABUF_ENABLE=0` | 0 | Bypass DMA-BUF (not supported in nvproxy), use peermem |
| `NCCL_NET_GDR_LEVEL=3` | 3 (PHB) | Enable GDRDMA for GPU memory |
| `NCCL_NET_GDR_LEVEL=0` | 0 | Disable GDRDMA (CPU-staged) |
| `NCCL_IB_HCA=mlx5_1` | device name | Restrict to a specific IB device |
| `NCCL_IB_HCA=^mlx5_0` | ^device | Exclude a device (use for mixed RoCE/IB) |
| `NCCL_DEBUG=INFO` | INFO/WARN/TRACE | NCCL log verbosity |

### Docker flags

| Flag | Purpose |
|---|---|
| `--gpus all` | Expose all GPUs via nvidia-container-toolkit |
| `--network=host` | Use host network namespace (needed for NCCL bootstrap) |
| `--ulimit memlock=-1:-1` | Unlimited locked memory (required for MR registration) |
| `--shm-size=1g` | Shared memory for NCCL proxy buffers (default 64MB is too small) |
| `--device=/dev/infiniband/uverbsN` | Expose uverbs device to the container |

---

## 8. Log inspection

### Sentry boot logs

```bash
BOOTLOG=$(ls -t /tmp/runsc-rdma/logs/ | grep boot | head -1)

# RDMA proxy activity
grep 'rdmaproxy' /tmp/runsc-rdma/logs/$BOOTLOG

# Peermem detection
grep 'peermem' /tmp/runsc-rdma/logs/$BOOTLOG

# Sysfs data collection
grep 'rdma collect' /tmp/runsc-rdma/logs/$BOOTLOG

# Page mirroring (MR registration)
grep 'mirrorSandbox\|GPU VA passthrough' /tmp/runsc-rdma/logs/$BOOTLOG
```

### Expected log lines for a healthy GDRDMA run

```
rdma collect: nvidia_peermem version="580.95.05" (from /sys/module/nvidia_peermem/version)
rdma collect: collected 9 device(s)
rdma sysfs: building virtual sysfs for 9 device(s)
rdmaproxy: opened /dev/infiniband/uverbs1 ...
rdmaproxy: proxy device fallback failed ..., GPU VA passthrough (nvidia-peermem)
```

The "proxy device fallback failed" + "GPU VA passthrough" message is normal —
it means GPU device memory can't be pinned by the sentry (expected), so the VA
is passed through to the host where nvidia-peermem resolves it.

---

## 9. Troubleshooting

### GDR shows 0 (GDRDMA not active)

1. Check `nvidia_peermem` is loaded: `lsmod | grep nvidia_peermem`
2. Check peermem was collected: `grep peermem /tmp/runsc-rdma/logs/$BOOTLOG`
3. Check `NCCL_DMABUF_ENABLE=0` is set
4. Check `NCCL_NET_GDR_LEVEL=3` is set

### Low bandwidth with many GPUs

Check Docker's available CPUs:

```bash
sudo docker info 2>&1 | grep CPUs
```

NCCL needs ~2 CPU cores per GPU for proxy threads. If Docker reports fewer
CPUs than `2 * num_gpus`, bandwidth will be CPU-bottlenecked. This affects
both gVisor and host/runc equally. Run the host baseline to confirm.

### "Remote RoCE device is incompatible with the local IB" error

Mixed RoCE/IB link types. Exclude the RoCE device:

```bash
-e 'NCCL_IB_HCA=^mlx5_0'
```

### "Call to ibv_get_async_event failed" warning

Known issue — gVisor doesn't fully support async event polling on uverbs FDs.
This warning is non-blocking; NCCL continues past it.

### Binary doesn't reflect code changes

Bazel's Docker volume cache can be stale. Clean and rebuild:

```bash
sudo docker exec gvisor-bazel-$(tools/compat/realpath.py . | md5sum | cut -c1-8)-x86_64 \
  bazel clean --expunge
sudo make copy TARGETS=runsc DESTINATION=/tmp
```

Then verify with `strings /tmp/runsc | grep "some_unique_string"` before
deploying.

### Container fails to start

Check the runsc create log:

```bash
ls -t /tmp/runsc-rdma/logs/ | head -5
cat /tmp/runsc-rdma/logs/$(ls -t /tmp/runsc-rdma/logs/ | grep create | head -1)
```

---

## 10. Quick copy-paste: full rebuild + test cycle

```bash
# Build
cd ~/gvisor
sudo make copy TARGETS=runsc DESTINATION=/tmp

# Deploy
sudo pkill -f "runsc-rdma" 2>/dev/null; sleep 1
sudo rm -f /usr/local/bin/runsc-rdma
sudo cp /tmp/runsc /usr/local/bin/runsc-rdma
sudo chmod +x /usr/local/bin/runsc-rdma

# Clear logs
sudo rm -rf /tmp/runsc-rdma/logs && sudo mkdir -p /tmp/runsc-rdma/logs

# Build test image (only needed once or after Dockerfile changes)
sudo docker build -f Dockerfile.nccl -t nccl-test .

# Run GDRDMA test (2 GPU, ~25 GB/s)
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=INFO \
  -e NCCL_P2P_DISABLE=1 \
  -e NCCL_SHM_DISABLE=1 \
  -e NCCL_DMABUF_ENABLE=0 \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_IB_HCA=mlx5_1 \
  nccl-test all_reduce_perf -b 8 -e 128M -f 2 -g 2
```
