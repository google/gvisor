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

Same image, same flags, but with the default Docker runtime (runc) instead of
gVisor. This is the proper apples-to-apples baseline — the container
environment ensures NCCL's topology detection matches the gVisor test.

> **Why not bare-metal?** With `NCCL_P2P_DISABLE=1` and `NCCL_SHM_DISABLE=1`
> on bare metal, NCCL sees 8 GPUs with no local interconnect and classifies
> them as 8 separate nodes (`nNodes 8 localRanks 1`). This breaks ring GDR
> heuristics and tanks performance (~1.5 GB/s). Those flags only exist to
> match gVisor's constraints — on real bare metal you'd use NVLink/P2P.

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runc --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=INFO \
  -e NCCL_P2P_DISABLE=1 \
  -e NCCL_SHM_DISABLE=1 \
  -e NCCL_DMABUF_ENABLE=0 \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e 'NCCL_IB_HCA=^mlx5_0' \
  nccl-test all_reduce_perf -b 8 -e 128M -f 2 -g 8
```

---

## 7. Multi-node NCCL all-reduce (2+ nodes over IB)

Validates InfiniBand performance between nodes using the official nccl-tests
with MPI. Requires 2+ machines on the same IB fabric with GPUs and IB NICs.

### HCA selection on Crusoe H200 nodes

On the two Crusoe H200 nodes used for validation on March 27, 2026, these HCAs
were **management devices** and should not be used for the data path:

- `mlx5_1`
- `mlx5_2`
- `mlx5_7`
- `mlx5_8`

The working data-path HCA list was:

```bash
export NCCL_IB_HCA_LIST=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11
```

For OOB/bootstrap traffic, `eth0` was the correct interface on both nodes.

### Prerequisites

- Docker installed on all nodes
- Same `Dockerfile.nccl` and source files available on all nodes
- OpenMPI installed on all nodes (check: `ls /usr/mpi/gcc/openmpi-*/bin/mpirun`)
- `nvidia-peermem` kernel module loaded on all nodes

### One-time setup (all nodes)

**1. Build the Docker image and extract binaries:**

```bash
sudo docker build -t nccl-test -f Dockerfile.nccl .

sudo docker create --name lib-tmp nccl-test
sudo rm -rf /tmp/nccl-tests-build /tmp/nccl-cuda-libs /tmp/nccl-mpi-libs
sudo docker cp lib-tmp:/nccl-tests/build/ /tmp/nccl-tests-build/
sudo docker cp lib-tmp:/usr/local/cuda/lib64/ /tmp/nccl-cuda-libs/
sudo mkdir -p /tmp/nccl-mpi-libs
for lib in libmpi.so.40 libmpi.so.40.30.2 \
           libopen-pal.so.40 libopen-pal.so.40.30.2 \
           libopen-rte.so.40 libopen-rte.so.40.30.2 \
           libhwloc.so.15 libhwloc.so.15.5.2 \
           libevent_pthreads-2.1.so.7 libevent_pthreads-2.1.so.7.0.1 \
           libevent_core-2.1.so.7 libevent_core-2.1.so.7.0.1; do
  sudo docker cp "lib-tmp:/usr/lib/x86_64-linux-gnu/$lib" /tmp/nccl-mpi-libs/ 2>/dev/null
done
sudo docker rm lib-tmp
```

**2. Load nvidia-peermem for GPUDirect RDMA:**

```bash
sudo modprobe nvidia-peermem
```

**3. Set up SSH keys (from the launch node to all other nodes):**

On the node you'll run mpirun from:

```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519.pub
```

Copy the public key into `~/.ssh/authorized_keys` on every other node:

```bash
# On each remote node:
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo '<paste public key here>' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Verify: `ssh -o StrictHostKeyChecking=no <remote_ip> echo OK`

### Identify node IPs

Find the private IP on each node (use the interface on the same subnet, not
loopback or docker bridges):

```bash
ip -4 addr show | grep -E 'inet 172\.|inet 10\.' | grep -v docker | grep -v 127
```

### Create hostfile

On the launch node, create `/tmp/hostfile` with one line per node. `slots=N`
is the number of GPUs per node:

```bash
cat > /tmp/hostfile <<'EOF'
<NODE_A_IP> slots=8
<NODE_B_IP> slots=8
EOF
```

### Run the test

```bash
MPI=$(ls -d /usr/mpi/gcc/openmpi-*/bin | head -1)
NGPUS_PER_NODE=8
NNODES=$(wc -l < /tmp/hostfile)
NP=$((NGPUS_PER_NODE * NNODES))
NIC_IF=eth0
NCCL_IB_HCA_LIST=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11

sudo $MPI/mpirun --allow-run-as-root \
  -np $NP -N $NGPUS_PER_NODE -hostfile /tmp/hostfile \
  --bind-to none \
  -mca btl tcp,self \
  -mca btl_tcp_if_include $NIC_IF \
  -mca plm_rsh_args "-o StrictHostKeyChecking=no" \
  -x LD_LIBRARY_PATH=/tmp/nccl-cuda-libs:/tmp/nccl-mpi-libs \
  -x NCCL_DEBUG=INFO \
  -x NCCL_SOCKET_IFNAME=$NIC_IF \
  -x NCCL_IB_HCA=$NCCL_IB_HCA_LIST \
  -x NCCL_NET_GDR_LEVEL=3 \
  /tmp/nccl-tests-build/all_reduce_perf -b 8M -e 2048M -f 2 -t 1 -g 1 -c 1 -n 10
```

**What to look for:**
- `nNodes 2` (or however many nodes) in the NCCL init logs
- `GDR 1` on all ranks
- `NET/IB` channels using `GDRDMA`
- busbw >200 GB/s at large message sizes for 2x H100 nodes (8 IB NICs each)

### TCP-bootstrap benchmark (what we ran)

For the March 27, 2026 validation run, we used `nccl_multinode_bench` instead
of MPI so we could compare the exact same workload across:

- extracted host binary
- `docker --runtime=runc`
- `docker --runtime=runsc-rdma`

This exercises the same NCCL IB/GDRDMA data path and was easier to launch
reliably across two nodes.

Assume:

- node A IP: `172.29.14.130`
- node B IP: `172.29.13.202`
- OOB/bootstrap interface: `eth0`
- data HCAs: `mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11`

**1. Extract the helper binary from the image (all nodes):**

```bash
sudo docker create --name lib-tmp nccl-test
sudo docker cp lib-tmp:/usr/local/bin/nccl_multinode_bench /tmp/nccl_multinode_bench
sudo docker rm lib-tmp
```

**2. Host-style baseline using the extracted binary**

Start rank 1 on node B first:

```bash
sudo bash -c 'ulimit -l unlimited && \
RANK=1 NRANKS=2 NGPUS=8 \
MASTER_ADDR=172.29.14.130 MASTER_PORT=29500 \
NCCL_DEBUG=INFO \
NCCL_SOCKET_IFNAME=eth0 \
NCCL_IB_HCA="mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11" \
NCCL_NET_GDR_LEVEL=3 \
LD_LIBRARY_PATH=/tmp/nccl-cuda-libs \
/tmp/nccl_multinode_bench'
```

Then start rank 0 on node A:

```bash
sudo bash -c 'ulimit -l unlimited && \
RANK=0 NRANKS=2 NGPUS=8 \
MASTER_ADDR=172.29.14.130 MASTER_PORT=29500 \
NCCL_DEBUG=INFO \
NCCL_SOCKET_IFNAME=eth0 \
NCCL_IB_HCA="mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11" \
NCCL_NET_GDR_LEVEL=3 \
LD_LIBRARY_PATH=/tmp/nccl-cuda-libs \
/tmp/nccl_multinode_bench'
```

Observed result on 2x8 H200 nodes:

- `nNodes 2`
- `NET/IB/.../GDRDMA` on the inter-node channels
- ~`307.99 GB/s` bus bandwidth at `134217728` bytes

**3. Container baseline with `runc`**

Start rank 1 on node B first:

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runc --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e RANK=1 -e NRANKS=2 -e NGPUS=8 \
  -e MASTER_ADDR=172.29.14.130 -e MASTER_PORT=29502 \
  -e NCCL_DEBUG=INFO \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11 \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  nccl-test /usr/local/bin/nccl_multinode_bench
```

Then start rank 0 on node A:

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runc --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e RANK=0 -e NRANKS=2 -e NGPUS=8 \
  -e MASTER_ADDR=172.29.14.130 -e MASTER_PORT=29502 \
  -e NCCL_DEBUG=INFO \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11 \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  nccl-test /usr/local/bin/nccl_multinode_bench
```

Observed result on 2x8 H200 nodes:

- ~`306.69 GB/s` bus bandwidth at `134217728` bytes
- This matches the extracted host baseline, so the containerized setup is sane

**4. gVisor run with `runsc-rdma`**

Start rank 1 on node B first:

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e RANK=1 -e NRANKS=2 -e NGPUS=8 \
  -e MASTER_ADDR=172.29.14.130 -e MASTER_PORT=29501 \
  -e NCCL_DEBUG=INFO \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11 \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  nccl-test /usr/local/bin/nccl_multinode_bench
```

Then start rank 0 on node A:

```bash
DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e RANK=0 -e NRANKS=2 -e NGPUS=8 \
  -e MASTER_ADDR=172.29.14.130 -e MASTER_PORT=29501 \
  -e NCCL_DEBUG=INFO \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11 \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  nccl-test /usr/local/bin/nccl_multinode_bench
```

Observed result on 2x8 H200 nodes:

- `nNodes 2`
- `NET/IB/.../GDRDMA` still appears in NCCL logs
- gVisor boot logs show `nvidia_peermem` detection and RDMA sysfs collection
- only ~`10.78 GB/s` bus bandwidth at `134217728` bytes

This is far below the matching host and `runc` baselines, so the regression is
specific to `runsc-rdma`, not the node pairing, SSH/bootstrap setup, or HCA
selection.

---

## 8. Environment variables reference

| Variable | Value | Purpose |
|---|---|---|
| `NCCL_P2P_DISABLE=1` | 1 | Disable NVLink, force IB transport |
| `NCCL_SHM_DISABLE=1` | 1 | Disable shared memory, force IB transport |
| `NCCL_DMABUF_ENABLE=0` | 0 | Bypass DMA-BUF (not supported in nvproxy), use peermem |
| `NCCL_NET_GDR_LEVEL=3` | 3 (PHB) | Enable GDRDMA for GPU memory |
| `NCCL_NET_GDR_LEVEL=0` | 0 | Disable GDRDMA (CPU-staged) |
| `NCCL_IB_HCA=mlx5_1` | device name | Restrict to a specific IB device |
| `NCCL_IB_HCA=mlx5_0,mlx5_3,...` | device list | Use an explicit HCA allowlist when some HCAs are management-only |
| `NCCL_IB_HCA=^mlx5_0` | ^device | Exclude a device (useful for mixed-link hosts, but explicit allowlists are safer) |
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

## 9. Log inspection

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

## 10. Troubleshooting

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

### Multi-node works but is far slower under gVisor

If the 2-node test completes and still shows `NET/IB/.../GDRDMA`, but
`runsc-rdma` is much slower than host or `runc`, use this checklist.

**1. First prove the test setup is sane**

Run the same 2-node workload three ways:

- extracted host binary
- `docker --runtime=runc`
- `docker --runtime=runsc-rdma`

Expected on the validated 2x8 H200 setup:

- extracted host binary: ~308 GB/s bus bandwidth at `134217728` bytes
- `runc`: ~307 GB/s
- `runsc-rdma`: currently ~10.8 GB/s

If host or `runc` is also slow (for example single-digit GB/s), stop there.
The issue is with node selection, HCA selection, bootstrap interface, or the
test environment, not gVisor.

**2. Verify both nodes use the same working HCA allowlist**

On the validated Crusoe H200 nodes, these were management devices and should
not be used for the data path:

- `mlx5_1`
- `mlx5_2`
- `mlx5_7`
- `mlx5_8`

Use:

```bash
export NCCL_SOCKET_IFNAME=eth0
export NCCL_IB_HCA=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11
```

Confirm device state on both nodes:

```bash
ibv_devinfo | sed -n '1,260p'
```

**3. Verify this is really GDRDMA, not a fallback**

In the NCCL logs, confirm all of the following:

- `nNodes 2`
- `Bootstrap: Using eth0:...`
- `NCCL_IB_HCA set to ...` with the expected allowlist
- `NET/IB : Using ...`
- inter-node channels show `via NET/IB/.../GDRDMA`

If `NET/Socket` appears, or `GDRDMA` disappears, you are debugging the wrong
problem.

**4. Verify peermem and RDMA sysfs were collected inside gVisor**

On both nodes:

```bash
BOOTLOG=$(ls -t /tmp/runsc-rdma/logs | grep boot | head -1)
grep 'peermem' /tmp/runsc-rdma/logs/$BOOTLOG
grep 'rdma collect' /tmp/runsc-rdma/logs/$BOOTLOG
```

You want to see:

- `nvidia_peermem version=...`
- all expected uverbs devices collected
- active 400 Gb/sec HCAs present in the boot log

**5. Force the known-good peermem path**

For gVisor multi-node runs, keep:

```bash
-e NCCL_DMABUF_ENABLE=0
-e NCCL_NET_GDR_LEVEL=3
```

Without `NCCL_DMABUF_ENABLE=0`, NCCL may try the DMA-BUF path, which nvproxy
does not currently support well enough.

**6. Compare only like-for-like runs**

Do not compare:

- bare metal vs gVisor
- different NCCL versions
- different HCA lists
- different bootstrap interfaces

Use the same `nccl-test` image and same env vars for `runc` and
`runsc-rdma`. That isolates the regression to gVisor itself.

**7. Check whether the slowdown is in initialization or steady state**

In both `runc` and `runsc-rdma` NCCL logs, compare:

- `Init timings - ncclCommInitRank`
- channel count lines
- final bandwidth table at large message sizes

If init is slower but steady-state bandwidth is fine, focus on setup overhead.
If init is acceptable but large-message bandwidth collapses, focus on the
steady-state RDMA path.

**8. If GDRDMA is present but bandwidth is still bad, inspect these first**

1. RDMA ioctl overhead in the hot path
2. CQ/QP/doorbell mmap behavior that preserves correctness but adds latency
3. Interaction between nvproxy and rdmaproxy in multi-node GDRDMA mode
4. Proxy-service thread scheduling or CPU placement unique to `runsc-rdma`

This case is what we currently observe: functional `NET/IB/.../GDRDMA`, but
~30x lower throughput than the matching `runc` baseline.

**9. Useful side-by-side log commands**

```bash
# Local gVisor boot log
BOOTLOG=$(ls -t /tmp/runsc-rdma/logs | grep boot | head -1)
sed -n '1,240p' /tmp/runsc-rdma/logs/$BOOTLOG

# NCCL result table from a saved run
rg '^( *size\\(B\\)| *8388608| *16777216| *33554432| *67108864| *134217728)' /tmp/nccl-*.log

# Remote node boot log
ssh <node-b> 'BOOTLOG=$(ls -t /tmp/runsc-rdma/logs | grep boot | head -1); sed -n "1,240p" /tmp/runsc-rdma/logs/$BOOTLOG'
```

**10. Current working hypothesis**

Because the gVisor run still reports `NET/IB/.../GDRDMA`, the bug is probably
not a simple transport fallback. Treat it as a **performance bug in the gVisor
RDMA path**, not as a missing-feature bug.

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

## 11. Quick copy-paste: full rebuild + test cycle

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
