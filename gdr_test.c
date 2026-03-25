#include <cuda.h>
#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LOG(fmt, ...) fprintf(stderr, "gdr_test: " fmt "\n", ##__VA_ARGS__)

#define CHECK_CUDA(call) do { \
	CUresult r = (call); \
	if (r != CUDA_SUCCESS) { \
		const char *err = "unknown"; \
		cuGetErrorString(r, &err); \
		LOG("CUDA error at line %d: %s (code %d)", __LINE__, err, (int)r); \
		return 1; \
	} \
} while (0)

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	LOG("starting");

	LOG("step 1: cuInit");
	CHECK_CUDA(cuInit(0));

	int dev_count;
	CHECK_CUDA(cuDeviceGetCount(&dev_count));
	LOG("step 2: %d CUDA devices", dev_count);
	if (dev_count == 0) { LOG("no CUDA devices"); return 1; }

	CUdevice cu_dev;
	CHECK_CUDA(cuDeviceGet(&cu_dev, 0));
	char name[256];
	CHECK_CUDA(cuDeviceGetName(name, sizeof(name), cu_dev));
	LOG("step 3: GPU 0 = %s", name);

	LOG("step 4: cuCtxCreate");
	CUcontext cu_ctx;
	CHECK_CUDA(cuCtxCreate(&cu_ctx, 0, cu_dev));
	LOG("step 4: OK");

	size_t gpu_size = 1 << 20;
	CUdeviceptr gpu_buf;
	LOG("step 5: cuMemAlloc %zu bytes", gpu_size);
	CHECK_CUDA(cuMemAlloc(&gpu_buf, gpu_size));
	LOG("step 5: GPU buffer at %p", (void *)gpu_buf);

	unsigned char probe;
	CUresult probe_r = cuMemcpyDtoH(&probe, gpu_buf, 1);
	LOG("step 6: GPU->CPU probe: %s", probe_r == CUDA_SUCCESS ? "OK" : "FAILED");

	int num_ib;
	struct ibv_device **dev_list = ibv_get_device_list(&num_ib);
	if (!dev_list || num_ib == 0) { LOG("no IB devices"); return 1; }
	LOG("step 7: %d IB devices, using %s", num_ib, ibv_get_device_name(dev_list[0]));

	struct ibv_context *ib_ctx = ibv_open_device(dev_list[0]);
	if (!ib_ctx) { LOG("ibv_open_device: %s", strerror(errno)); return 1; }
	LOG("step 8: device opened");

	struct ibv_pd *pd = ibv_alloc_pd(ib_ctx);
	if (!pd) { LOG("ibv_alloc_pd: %s", strerror(errno)); return 1; }
	LOG("step 9: PD OK");

	/* CPU MR baseline */
	LOG("step 10: CPU MR reg (baseline)");
	size_t cpu_size = 65536;
	void *cpu_buf = malloc(cpu_size);
	memset(cpu_buf, 0x42, cpu_size);
	struct ibv_mr *cpu_mr = ibv_reg_mr(pd, cpu_buf, cpu_size,
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	if (!cpu_mr) {
		LOG("CPU MR FAILED: %s (errno=%d)", strerror(errno), errno);
	} else {
		LOG("CPU MR OK: lkey=%u rkey=%u", cpu_mr->lkey, cpu_mr->rkey);
		ibv_dereg_mr(cpu_mr);
	}
	free(cpu_buf);

	/* GPU MR -- the actual GPUDirect RDMA test */
	LOG("step 11: GPU MR reg (GPUDirect RDMA) addr=%p size=%zu", (void *)gpu_buf, gpu_size);
	struct ibv_mr *gpu_mr = ibv_reg_mr(pd, (void *)gpu_buf, gpu_size,
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	if (!gpu_mr) {
		LOG("GPU MR FAILED: %s (errno=%d)", strerror(errno), errno);
	} else {
		LOG("GPU MR OK: lkey=%u rkey=%u -- GPUDirect RDMA WORKS!", gpu_mr->lkey, gpu_mr->rkey);
		ibv_dereg_mr(gpu_mr);
	}

	ibv_dealloc_pd(pd);
	ibv_close_device(ib_ctx);
	ibv_free_device_list(dev_list);
	cuMemFree(gpu_buf);
	cuCtxDestroy(cu_ctx);

	LOG("done");
	return 0;
}
