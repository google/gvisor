#include <cuda.h>
#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CHECK_CUDA(call) do { \
	CUresult r = (call); \
	if (r != CUDA_SUCCESS) { \
		const char *err; \
		cuGetErrorString(r, &err); \
		fprintf(stderr, "CUDA error at %s:%d: %s\n", __FILE__, __LINE__, err); \
		return 1; \
	} \
} while (0)

int main(void) {
	CHECK_CUDA(cuInit(0));

	int dev_count;
	CHECK_CUDA(cuDeviceGetCount(&dev_count));
	printf("CUDA devices: %d\n", dev_count);
	if (dev_count == 0) {
		fprintf(stderr, "No CUDA devices\n");
		return 1;
	}

	CUdevice cu_dev;
	CHECK_CUDA(cuDeviceGet(&cu_dev, 0));

	char name[256];
	CHECK_CUDA(cuDeviceGetName(name, sizeof(name), cu_dev));
	printf("GPU 0: %s\n", name);

	CUcontext cu_ctx;
	CHECK_CUDA(cuCtxCreate(&cu_ctx, 0, cu_dev));

	size_t gpu_size = 1 << 20; /* 1 MiB */
	CUdeviceptr gpu_buf;
	CHECK_CUDA(cuMemAlloc(&gpu_buf, gpu_size));
	printf("GPU buffer: addr=%p size=%zu\n", (void *)gpu_buf, gpu_size);

	/* Probe: can we read the GPU pointer from CPU? (UVM should allow this) */
	unsigned char probe;
	CUresult probe_r = cuMemcpyDtoH(&probe, gpu_buf, 1);
	printf("GPU→CPU probe: %s\n",
	       probe_r == CUDA_SUCCESS ? "OK (UVM mapping exists)" : "FAILED (no CPU mapping)");

	/* Open IB device */
	int num_ib;
	struct ibv_device **dev_list = ibv_get_device_list(&num_ib);
	if (!dev_list || num_ib == 0) {
		fprintf(stderr, "No IB devices\n");
		return 1;
	}
	printf("IB devices: %d, using %s\n", num_ib, ibv_get_device_name(dev_list[0]));

	struct ibv_context *ib_ctx = ibv_open_device(dev_list[0]);
	if (!ib_ctx) {
		fprintf(stderr, "ibv_open_device: %s\n", strerror(errno));
		return 1;
	}

	struct ibv_pd *pd = ibv_alloc_pd(ib_ctx);
	if (!pd) {
		fprintf(stderr, "ibv_alloc_pd: %s\n", strerror(errno));
		return 1;
	}
	printf("PD OK\n");

	/* Test 1: CPU MR (known working, baseline) */
	size_t cpu_size = 65536;
	void *cpu_buf = malloc(cpu_size);
	memset(cpu_buf, 0x42, cpu_size);
	struct ibv_mr *cpu_mr = ibv_reg_mr(pd, cpu_buf, cpu_size,
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	if (!cpu_mr) {
		fprintf(stderr, "ibv_reg_mr(CPU) FAILED: %s\n", strerror(errno));
	} else {
		printf("CPU MR OK: lkey=%u rkey=%u addr=%p len=%zu\n",
		       cpu_mr->lkey, cpu_mr->rkey, cpu_mr->addr, cpu_mr->length);
		ibv_dereg_mr(cpu_mr);
		printf("CPU MR deregistered\n");
	}
	free(cpu_buf);

	/* Test 2: GPU MR (GPUDirect RDMA) */
	printf("\n--- GPUDirect RDMA test ---\n");
	printf("Registering GPU VA %p with NIC...\n", (void *)gpu_buf);
	struct ibv_mr *gpu_mr = ibv_reg_mr(pd, (void *)gpu_buf, gpu_size,
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	if (!gpu_mr) {
		fprintf(stderr, "ibv_reg_mr(GPU) FAILED: %s (errno=%d)\n", strerror(errno), errno);
		fprintf(stderr, "  This means nvidia-peermem could not resolve GPU VA in sentry context.\n");
		fprintf(stderr, "  GPU VA %p may not be visible to the sentry process.\n", (void *)gpu_buf);
	} else {
		printf("GPU MR OK: lkey=%u rkey=%u addr=%p len=%zu\n",
		       gpu_mr->lkey, gpu_mr->rkey, gpu_mr->addr, gpu_mr->length);
		printf("  GPUDirect RDMA is WORKING!\n");
		ibv_dereg_mr(gpu_mr);
		printf("GPU MR deregistered\n");
	}

	ibv_dealloc_pd(pd);
	ibv_close_device(ib_ctx);
	ibv_free_device_list(dev_list);
	cuMemFree(gpu_buf);
	cuCtxDestroy(cu_ctx);

	printf("\nDone.\n");
	return 0;
}
