# PyTorch Two-Node All-Reduce Test

This file describes how to run the provided `torch.distributed` all-reduce
benchmark across the two H200 nodes we validated:

- node A / launch node: `172.29.5.7`
- node B / remote node: `172.29.11.158`

Assumptions:

- node A can SSH to node B without a password
- Docker is installed on both nodes
- `runsc-rdma` is already deployed on both nodes if you want the gVisor run
- both nodes expose all 8 H200 GPUs and the IB HCAs

## 1. Quick preflight

From node A:

```bash
hostname
ip -4 addr show eth0 | sed -n '1,3p'
nvidia-smi --query-gpu=index,name --format=csv,noheader
sudo docker info --format '{{.NCPU}}'
```

From node A, verify node B:

```bash
ssh -o StrictHostKeyChecking=no 172.29.11.158 '
hostname
ip -4 addr show eth0 | sed -n "1,3p"
nvidia-smi --query-gpu=index,name --format=csv,noheader
sudo docker info --format "{{.NCPU}}"
'
```

Expected:

- both nodes report 8x `NVIDIA H200`
- node A is `172.29.5.7`
- node B is `172.29.11.158`
- both nodes report a healthy Docker CPU count

## 2. Build a PyTorch image on both nodes

This repo already has a CUDA 12.4 PyTorch image definition. Build it locally
and remotely from node A:

```bash
cd ~/gvisor
sudo docker build -t gvisor-pytorch -f images/gpu/pytorch/Dockerfile.x86_64 images/gpu/pytorch
ssh -o StrictHostKeyChecking=no 172.29.11.158 '
cd ~/gvisor && sudo docker build -t gvisor-pytorch -f images/gpu/pytorch/Dockerfile.x86_64 images/gpu/pytorch
'
```

## 3. Write the benchmark script

The snippet below is the provided benchmark with one required fix:
`timed_allreduce()` used `local_rank` without receiving it as an argument.

Create the script on node A:

```bash
cat > /tmp/torch_allreduce_bench.py <<'PY'
import os

import torch
import torch.distributed as dist

# Default settings from EleutherAI cookbook
WARMUP_ITERS, TRIALS = 5, 50

# These emulate the payload which will become a M * N * 4-sized tensor below.
N = 500000
M = 2000


def sync_all():
    torch.cuda.synchronize()
    dist.barrier()


def timed_allreduce(mat, local_rank, start_event, end_event, warmup_iters, iters):
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
    size = M * N * 4  # 4 bytes per fp32 element
    algbw = torch.tensor([size / avg_duration], device=f"cuda:{local_rank}")

    dist.reduce(algbw, dst=0, op=dist.ReduceOp.SUM)
    algbw /= n

    return algbw.item()


def run(local_rank):
    is_global_rank_0 = dist.get_rank() == 0

    mat = torch.rand(N, M, dtype=torch.float32, device=f"cuda:{local_rank}")

    start_event = torch.cuda.Event(enable_timing=True)
    end_event = torch.cuda.Event(enable_timing=True)

    algbw = timed_allreduce(
        mat,
        local_rank=local_rank,
        start_event=start_event,
        end_event=end_event,
        warmup_iters=WARMUP_ITERS,
        iters=TRIALS,
    )

    n = dist.get_world_size()
    busbw = algbw * (2 * (n - 1) / n)

    if is_global_rank_0:
        print(
            f"The average bandwidth of all_reduce with a {M * N * 4 / 1e9}GB payload ({TRIALS} trials, {n} ranks):\n",
            f"algbw: {algbw / 1e9:.3f} GBps ({algbw * 8 / 1e9:.1f} Gbps)\n",
            f"busbw: {busbw / 1e9:.3f} GBps ({busbw * 8 / 1e9:.1f} Gbps)\n",
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
```

Copy it to node B:

```bash
scp /tmp/torch_allreduce_bench.py 172.29.11.158:/tmp/torch_allreduce_bench.py
```

## 4. Common environment

On node A:

```bash
export NODE_A_IP=172.29.5.7
export NODE_B_IP=172.29.11.158
export MASTER_PORT_RUNC=29520
export MASTER_PORT_RUNSC=29521
export NCCL_SOCKET_IFNAME=eth0
export NCCL_IB_HCA=mlx5_0,mlx5_3,mlx5_4,mlx5_5,mlx5_6,mlx5_9,mlx5_10,mlx5_11
export NCCL_NET_GDR_LEVEL=3
export NCCL_DMABUF_ENABLE=0
export NCCL_DEBUG=WARN
export DOCKER_CPUS=$(($(sudo docker info --format '{{.NCPU}}') - 2))
if [ "$DOCKER_CPUS" -lt 1 ]; then export DOCKER_CPUS=1; fi
export DEVS=$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
```

## 5. `runc` baseline

Launch rank 1 on node B from node A in the background:

```bash
ssh -o StrictHostKeyChecking=no "$NODE_B_IP" "
DOCKER_CPUS=\$((\$(sudo docker info --format '{{.NCPU}}') - 2))
if [ \"\$DOCKER_CPUS\" -lt 1 ]; then DOCKER_CPUS=1; fi
DEVS=\$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo docker rm -f torchbench-rank1-runc >/dev/null 2>&1 || true
nohup sudo docker run --name torchbench-rank1-runc --runtime=runc --rm --gpus all \$DEVS \
  --cpus=\"\$DOCKER_CPUS\" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=$NCCL_DEBUG \
  -e NCCL_SOCKET_IFNAME=$NCCL_SOCKET_IFNAME \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=$NCCL_NET_GDR_LEVEL \
  -e NCCL_DMABUF_ENABLE=$NCCL_DMABUF_ENABLE \
  -v /tmp/torch_allreduce_bench.py:/tmp/torch_allreduce_bench.py:ro \
  gvisor-pytorch torchrun \
    --nnodes=2 \
    --nproc_per_node=8 \
    --node_rank=1 \
    --master_addr=$NODE_A_IP \
    --master_port=$MASTER_PORT_RUNC \
    /tmp/torch_allreduce_bench.py \
  >/tmp/torchbench-rank1-runc.log 2>&1 < /dev/null &
"
```

Then start rank 0 on node A:

```bash
sudo docker rm -f torchbench-rank0-runc >/dev/null 2>&1 || true
sudo docker run --name torchbench-rank0-runc --runtime=runc --rm --gpus all $DEVS \
  --cpus="$DOCKER_CPUS" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=$NCCL_DEBUG \
  -e NCCL_SOCKET_IFNAME=$NCCL_SOCKET_IFNAME \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=$NCCL_NET_GDR_LEVEL \
  -e NCCL_DMABUF_ENABLE=$NCCL_DMABUF_ENABLE \
  -v /tmp/torch_allreduce_bench.py:/tmp/torch_allreduce_bench.py:ro \
  gvisor-pytorch torchrun \
    --nnodes=2 \
    --nproc_per_node=8 \
    --node_rank=0 \
    --master_addr=$NODE_A_IP \
    --master_port=$MASTER_PORT_RUNC \
    /tmp/torch_allreduce_bench.py | tee /tmp/torchbench-rank0-runc.log
```

Fetch the remote log if needed:

```bash
ssh "$NODE_B_IP" 'sed -n "1,120p" /tmp/torchbench-rank1-runc.log'
```

## 6. `runsc-rdma` run

Launch rank 1 on node B from node A in the background:

```bash
ssh -o StrictHostKeyChecking=no "$NODE_B_IP" "
DOCKER_CPUS=\$((\$(sudo docker info --format '{{.NCPU}}') - 2))
if [ \"\$DOCKER_CPUS\" -lt 1 ]; then DOCKER_CPUS=1; fi
DEVS=\$(ls /dev/infiniband/uverbs* | sed 's/^/--device=/' | tr '\n' ' ')
sudo rm -rf /tmp/runsc-rdma/logs && sudo mkdir -p /tmp/runsc-rdma/logs
sudo docker rm -f torchbench-rank1-runsc >/dev/null 2>&1 || true
nohup sudo docker run --name torchbench-rank1-runsc --runtime=runsc-rdma --rm --gpus all \$DEVS \
  --cpus=\"\$DOCKER_CPUS\" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=$NCCL_DEBUG \
  -e NCCL_SOCKET_IFNAME=$NCCL_SOCKET_IFNAME \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=$NCCL_NET_GDR_LEVEL \
  -e NCCL_DMABUF_ENABLE=$NCCL_DMABUF_ENABLE \
  -v /tmp/torch_allreduce_bench.py:/tmp/torch_allreduce_bench.py:ro \
  gvisor-pytorch torchrun \
    --nnodes=2 \
    --nproc_per_node=8 \
    --node_rank=1 \
    --master_addr=$NODE_A_IP \
    --master_port=$MASTER_PORT_RUNSC \
    /tmp/torch_allreduce_bench.py \
  >/tmp/torchbench-rank1-runsc.log 2>&1 < /dev/null &
"
```

Then start rank 0 on node A:

```bash
sudo rm -rf /tmp/runsc-rdma/logs && sudo mkdir -p /tmp/runsc-rdma/logs
sudo docker rm -f torchbench-rank0-runsc >/dev/null 2>&1 || true
sudo docker run --name torchbench-rank0-runsc --runtime=runsc-rdma --rm --gpus all $DEVS \
  --cpus="$DOCKER_CPUS" --ulimit memlock=-1:-1 --shm-size=1g --network=host \
  -e NCCL_DEBUG=$NCCL_DEBUG \
  -e NCCL_SOCKET_IFNAME=$NCCL_SOCKET_IFNAME \
  -e NCCL_IB_HCA=$NCCL_IB_HCA \
  -e NCCL_NET_GDR_LEVEL=$NCCL_NET_GDR_LEVEL \
  -e NCCL_DMABUF_ENABLE=$NCCL_DMABUF_ENABLE \
  -v /tmp/torch_allreduce_bench.py:/tmp/torch_allreduce_bench.py:ro \
  gvisor-pytorch torchrun \
    --nnodes=2 \
    --nproc_per_node=8 \
    --node_rank=0 \
    --master_addr=$NODE_A_IP \
    --master_port=$MASTER_PORT_RUNSC \
    /tmp/torch_allreduce_bench.py | tee /tmp/torchbench-rank0-runsc.log
```

Fetch the remote log if needed:

```bash
ssh "$NODE_B_IP" 'sed -n "1,120p" /tmp/torchbench-rank1-runsc.log'
```

## 7. Expected output

Rank 0 prints a summary like:

```text
Starting benchmark...
The average bandwidth of all_reduce with a 4.0GB payload (50 trials, 16 ranks):
 algbw: ...
 busbw: ...
```

Useful comparisons:

- `runc` bus bandwidth vs `runsc-rdma` bus bandwidth
- whether `runsc-rdma` is much slower even when NCCL still uses IB/GDRDMA

If you want more NCCL detail, rerun with:

```bash
export NCCL_DEBUG=INFO
```

That will make output noisier and logs from many ranks may interleave.

## 8. Useful debug commands

Check recent `runsc` logs on node A:

```bash
BOOTLOG=$(ls -t /tmp/runsc-rdma/logs | grep boot | head -1)
grep 'peermem' /tmp/runsc-rdma/logs/$BOOTLOG
grep 'rdma collect' /tmp/runsc-rdma/logs/$BOOTLOG
```

Check recent `runsc` logs on node B from node A:

```bash
ssh "$NODE_B_IP" '
BOOTLOG=$(ls -t /tmp/runsc-rdma/logs | grep boot | head -1)
grep peermem /tmp/runsc-rdma/logs/$BOOTLOG
grep "rdma collect" /tmp/runsc-rdma/logs/$BOOTLOG
'
```

If the 4GB payload is too large, lower `N` or `M` in `/tmp/torch_allreduce_bench.py`
on both nodes and rerun.
