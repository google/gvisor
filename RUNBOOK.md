# gVisor RDMA Proxy — End-to-End Runbook

Complete walkthrough: clone, build, deploy, validate RDMA, run NCCL and
PyTorch multi-node benchmarks comparing runc vs gVisor.

Assumes two H200 nodes with RDMA NICs (mlx5) and passwordless sudo.

---

## 1. Clone and build (both nodes)

```bash
git clone git@github.com:modal-labs/gvisor.git
cd gvisor
git checkout alessio/development

# Build runsc (~7 min first time, ~30s incremental)
sudo make copy TARGETS=runsc DESTINATION=/tmp
```

## 2. Deploy runsc-rdma (both nodes)

```bash
sudo pkill -f "runsc-rdma" 2>/dev/null; sleep 1
sudo rm -f /usr/local/bin/runsc-rdma
sudo cp /tmp/runsc /usr/local/bin/runsc-rdma
sudo chmod +x /usr/local/bin/runsc-rdma
```

## 3. Register Docker runtime (both nodes, once)

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

## 4. Load nvidia-peermem (both nodes)

```bash
sudo modprobe nvidia-peermem
```

## 5. Build Docker images (both nodes)

### NCCL test image

```bash
cd ~/gvisor
sudo docker build -f Dockerfile.nccl -t nccl-test .
```

### PyTorch image

```bash
cat > /tmp/Dockerfile.pytorch <<'EOF'
FROM nvidia/cuda:12.4.0-devel-ubuntu22.04
RUN apt-get update && apt-get install -y python3 python3-pip
RUN PIP_INDEX_URL="https://download.pytorch.org/whl/cu124" && \
    python3 -m pip install --ignore-installed \
        torch torchvision torchaudio \
        --index-url "$PIP_INDEX_URL"
EOF
sudo docker build -t gvisor-pytorch -f /tmp/Dockerfile.pytorch /tmp
```

## 6. Set up SSH keys (node A → node B)

On node A, generate a key if you don't have one:

```bash
# Skip if ~/.ssh/id_ed25519 already exists
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
```

Copy the public key to node B:

```bash
# Replace NODE_B_IP with node B's actual IP
NODE_B_IP=<node-b-ip>
ssh-copy-id -o StrictHostKeyChecking=no $NODE_B_IP
# Or manually: cat ~/.ssh/id_ed25519.pub | ssh $NODE_B_IP 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
```

Verify:

```bash
ssh -o StrictHostKeyChecking=no $NODE_B_IP echo OK
```

## 7. Identify node IPs and set environment

Run on both nodes to find IPs:

```bash
ip -4 addr show | grep -E 'inet (172\.|10\.)' | grep -v docker | grep -v 127
```

Set these on node A (replace with your actual IPs):

```bash
export NODE_A_IP=<node-a-ip>    # e.g. 172.29.5.7
export NODE_B_IP=<node-b-ip>    # e.g. 172.29.11.158
export DOCKER_CPUS=$(($(sudo docker info --format '{{.NCPU}}') - 2))
export DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
```

## 8. Quick RDMA validation with ib_write_bw

Verifies raw RDMA works between the two nodes before running NCCL.
Uses the RoCE/RDMA interface IPs (10.x.x.x on rdma0).

Find the RDMA IPs:

```bash
# On each node:
ip -4 addr show rdma0 | grep inet
# e.g. node A: 10.224.5.7, node B: 10.224.5.8
```

**Node B (server):**

```bash
ib_write_bw -d mlx5_0 -F --report_gbits
```

**Node A (client):**

```bash
# Replace with node B's rdma0 IP
ib_write_bw -d mlx5_0 -F --report_gbits <node-b-rdma0-ip>
```

Expected: ~400 Gbps for a single NDR link.

---

## 9. Generate NCCL topology file (node A, once)

gVisor doesn't expose PCI device sysfs, so NCCL can't discover the
NUMA/PCIe topology. Without this file, NCCL uses Ring (64 channels)
instead of NVLS Tree (16 channels) — an 8.6x performance hit.

```bash
sudo mkdir -p /tmp/nccl_shared
sudo docker run --runtime=runc --rm --gpus all $DEVS \
  --cpus="$DOCKER_CPUS" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_TOPO_DUMP_FILE=/shared/topo.xml \
  -e RANK=0 -e NRANKS=1 -e NGPUS=8 \
  -e MASTER_ADDR=127.0.0.1 -e MASTER_PORT=29517 \
  -v /tmp/nccl_shared:/shared \
  nccl-test /usr/local/bin/nccl_multinode_bench

# Copy to node B
scp /tmp/nccl_shared/topo.xml $NODE_B_IP:/tmp/nccl_topo.xml
cp /tmp/nccl_shared/topo.xml /tmp/nccl_topo.xml
```

---

## 10. NCCL multinode benchmark

### Identify which HCAs to use

Some HCAs are management-only. Check which are active data-path devices:

```bash
ibv_devinfo | grep -E 'hca_id|state|link_layer|rate'
```

Set the working HCA list (exclude management devices):

```bash
# Example for Crusoe H200 nodes — adjust for your hardware
export NCCL_IB_HCA=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11
```

### 10a. runc baseline

**Node B (rank 1) — run first:**

```bash
ssh -o StrictHostKeyChecking=no $NODE_B_IP "
DOCKER_CPUS=\$((\$(sudo docker info --format '{{.NCPU}}') - 2))
DEVS=\$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runc --rm --gpus all \$DEVS \
  --cpus=\"\$DOCKER_CPUS\" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e RANK=1 -e NRANKS=2 -e NGPUS=8 \
  -e MASTER_ADDR=$NODE_A_IP -e MASTER_PORT=29500 \
  -e NCCL_DEBUG=INFO \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  nccl-test /usr/local/bin/nccl_multinode_bench
"
```

**Node A (rank 0):**

```bash
sudo docker run --runtime=runc --rm --gpus all $DEVS \
  --cpus="$DOCKER_CPUS" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e RANK=0 -e NRANKS=2 -e NGPUS=8 \
  -e MASTER_ADDR=$NODE_A_IP -e MASTER_PORT=29500 \
  -e NCCL_DEBUG=INFO \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  nccl-test /usr/local/bin/nccl_multinode_bench
```

### 10b. runsc-rdma (gVisor)

**Node B (rank 1) — run first:**

```bash
ssh -o StrictHostKeyChecking=no $NODE_B_IP "
DOCKER_CPUS=\$((\$(sudo docker info --format '{{.NCPU}}') - 2))
DEVS=\$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo rm -rf /tmp/runsc-rdma/logs && sudo mkdir -p /tmp/runsc-rdma/logs
sudo docker run --runtime=runsc-rdma --rm --gpus all \$DEVS \
  --cpus=\"\$DOCKER_CPUS\" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -v /tmp/nccl_topo.xml:/topo.xml:ro \
  -e RANK=1 -e NRANKS=2 -e NGPUS=8 \
  -e MASTER_ADDR=$NODE_A_IP -e MASTER_PORT=29501 \
  -e NCCL_DEBUG=INFO \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  -e NCCL_IB_GID_INDEX=0 \
  -e NCCL_TOPO_FILE=/topo.xml \
  nccl-test /usr/local/bin/nccl_multinode_bench
"
```

**Node A (rank 0):**

```bash
sudo rm -rf /tmp/runsc-rdma/logs && sudo mkdir -p /tmp/runsc-rdma/logs
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --cpus="$DOCKER_CPUS" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -v /tmp/nccl_topo.xml:/topo.xml:ro \
  -e RANK=0 -e NRANKS=2 -e NGPUS=8 \
  -e MASTER_ADDR=$NODE_A_IP -e MASTER_PORT=29501 \
  -e NCCL_DEBUG=INFO \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  -e NCCL_IB_GID_INDEX=0 \
  -e NCCL_TOPO_FILE=/topo.xml \
  nccl-test /usr/local/bin/nccl_multinode_bench
```

---

## 11. PyTorch all-reduce benchmark

### Create the benchmark script (node A, then copy to B)

```bash
cat > /tmp/torch_allreduce_bench.py <<'PY'
import os
import torch
import torch.distributed as dist

WARMUP_ITERS, TRIALS = 5, 50
N = 500000
M = 2000

def sync_all():
    torch.cuda.synchronize()
    dist.barrier()

def timed_allreduce(mat, start_event, end_event, warmup_iters, iters):
    sync_all()
    for _ in range(warmup_iters):
        dist.all_reduce(mat)
    sync_all()
    start_event.record()
    for _ in range(iters):
        dist.all_reduce(mat)
    end_event.record()
    sync_all()
    duration = start_event.elapsed_time(end_event) / 1000
    avg_duration = duration / iters
    n = dist.get_world_size()
    size = M * N * 4
    algbw = torch.tensor([size / avg_duration]).cuda(local_rank)
    dist.reduce(algbw, dst=0, op=dist.ReduceOp.SUM)
    algbw /= n
    return algbw.item()

def run(local_rank):
    is_global_rank_0 = dist.get_rank() == 0
    mat = torch.rand(N, M, dtype=torch.float32).cuda(local_rank)
    start_event = torch.cuda.Event(enable_timing=True)
    end_event = torch.cuda.Event(enable_timing=True)
    algbw = timed_allreduce(mat, start_event, end_event, warmup_iters=WARMUP_ITERS, iters=TRIALS)
    n = dist.get_world_size()
    busbw = algbw * (2 * (n - 1) / n)
    if is_global_rank_0:
        print(
            f"The average bandwidth of all_reduce with a {M*N*4/1e9}GB payload ({TRIALS} trials, {n} ranks):\n",
            f"algbw: {algbw/1e9:.3f} GBps ({algbw*8/1e9:.1f} Gbps)\n",
            f"busbw: {busbw/1e9:.3f} GBps ({busbw*8/1e9:.1f} Gbps)\n",
        )

def init_processes(local_rank, fn, backend="nccl"):
    torch.cuda.set_device(local_rank)
    dist.init_process_group(backend, device_id=torch.device(f"cuda:{local_rank}"))
    if dist.get_rank() == 0:
        print("Starting benchmark...")
    fn(local_rank)
    sync_all()
    dist.destroy_process_group()

if __name__ == "__main__":
    local_rank = int(os.environ["LOCAL_RANK"])
    init_processes(local_rank=local_rank, fn=run)
PY

scp /tmp/torch_allreduce_bench.py $NODE_B_IP:/tmp/torch_allreduce_bench.py
```

### 11a. runc baseline

**Node B (rank 1) — run first:**

```bash
ssh -o StrictHostKeyChecking=no $NODE_B_IP "
DOCKER_CPUS=\$((\$(sudo docker info --format '{{.NCPU}}') - 2))
DEVS=\$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker run --runtime=runc --rm --gpus all \$DEVS \
  --cpus=\"\$DOCKER_CPUS\" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=WARN \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  -v /tmp/torch_allreduce_bench.py:/tmp/torch_allreduce_bench.py:ro \
  gvisor-pytorch torchrun \
    --nnodes=2 --nproc_per_node=8 --node_rank=1 \
    --master_addr=$NODE_A_IP --master_port=29530 \
    /tmp/torch_allreduce_bench.py
"
```

**Node A (rank 0):**

```bash
sudo docker run --runtime=runc --rm --gpus all $DEVS \
  --cpus="$DOCKER_CPUS" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=WARN \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  -v /tmp/torch_allreduce_bench.py:/tmp/torch_allreduce_bench.py:ro \
  gvisor-pytorch torchrun \
    --nnodes=2 --nproc_per_node=8 --node_rank=0 \
    --master_addr=$NODE_A_IP --master_port=29530 \
    /tmp/torch_allreduce_bench.py
```

### 11b. runsc-rdma (gVisor)

**Node B (rank 1) — run first:**

```bash
ssh -o StrictHostKeyChecking=no $NODE_B_IP "
DOCKER_CPUS=\$((\$(sudo docker info --format '{{.NCPU}}') - 2))
DEVS=\$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo rm -rf /tmp/runsc-rdma/logs && sudo mkdir -p /tmp/runsc-rdma/logs
sudo docker run --runtime=runsc-rdma --rm --gpus all \$DEVS \
  --cpus=\"\$DOCKER_CPUS\" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -v /tmp/nccl_topo.xml:/topo.xml:ro \
  -e NCCL_DEBUG=WARN \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  -e NCCL_IB_GID_INDEX=0 \
  -e NCCL_TOPO_FILE=/topo.xml \
  -v /tmp/torch_allreduce_bench.py:/tmp/torch_allreduce_bench.py:ro \
  gvisor-pytorch torchrun \
    --nnodes=2 --nproc_per_node=8 --node_rank=1 \
    --master_addr=$NODE_A_IP --master_port=29531 \
    /tmp/torch_allreduce_bench.py
"
```

**Node A (rank 0):**

```bash
sudo rm -rf /tmp/runsc-rdma/logs && sudo mkdir -p /tmp/runsc-rdma/logs
sudo docker run --runtime=runsc-rdma --rm --gpus all $DEVS \
  --cpus="$DOCKER_CPUS" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -v /tmp/nccl_topo.xml:/topo.xml:ro \
  -e NCCL_DEBUG=WARN \
  -e NCCL_SOCKET_IFNAME=eth0 \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=3 \
  -e NCCL_DMABUF_ENABLE=0 \
  -e NCCL_IB_GID_INDEX=0 \
  -e NCCL_TOPO_FILE=/topo.xml \
  -v /tmp/torch_allreduce_bench.py:/tmp/torch_allreduce_bench.py:ro \
  gvisor-pytorch torchrun \
    --nnodes=2 --nproc_per_node=8 --node_rank=0 \
    --master_addr=$NODE_A_IP --master_port=29531 \
    /tmp/torch_allreduce_bench.py
```

---

## 12. Expected results (2x8 H200 nodes, 112 CPUs each)

### NCCL multinode bench (128 MiB message)

| Runtime | busbw | Channels | Algorithm |
|---------|-------|----------|-----------|
| runc | ~125 GB/s | 16 | NVLS Tree |
| runsc-rdma + TOPO_FILE | ~79 GB/s | 16 | NVLS Tree |
| runsc-rdma (no TOPO_FILE) | ~15 GB/s | 64 | Ring |

### PyTorch all-reduce (4 GB payload, 50 trials)

| Runtime | busbw |
|---------|-------|
| runc | ~4.1 GBps |
| runsc-rdma + TOPO_FILE | ~3.0 GBps |

The ~1.4x gap with TOPO_FILE is general gVisor systrap/sentry overhead,
not RDMA-specific. Without TOPO_FILE the gap is ~8.6x due to NCCL
selecting Ring instead of NVLS Tree.

---

## 13. Troubleshooting

**Port in use**: If you get `EADDRINUSE`, change `--master_port` to a
different value. Each test pair (runc vs runsc) should use different ports.

**gVisor logs**: Check `/tmp/runsc-rdma/logs/` on each node for sentry
boot logs and RDMA proxy activity.

**NCCL debug**: Change `-e NCCL_DEBUG=WARN` to `-e NCCL_DEBUG=INFO` for
verbose NCCL output (noisy but useful for diagnosing transport issues).

**Verify NCCL topology**: With `NCCL_DEBUG=INFO`, check for:
- `16 coll channels` (not 64)
- `Connected NVLS tree` (not `Connected all rings`)
- `Symmetric VA size=140GB` without "Symmetric memory is not supported"
