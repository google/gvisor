#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <cuda_runtime.h>
#include <nccl.h>

#define CHECK_CUDA(cmd) do {                                       \
    cudaError_t e = cmd;                                           \
    if (e != cudaSuccess) {                                        \
        fprintf(stderr, "CUDA %s:%d: %s\n", __FILE__, __LINE__,   \
                cudaGetErrorString(e));                             \
        exit(1);                                                   \
    }                                                              \
} while (0)

#define CHECK_NCCL(cmd) do {                                       \
    ncclResult_t r = cmd;                                          \
    if (r != ncclSuccess) {                                        \
        fprintf(stderr, "NCCL %s:%d: %s\n", __FILE__, __LINE__,   \
                ncclGetErrorString(r));                             \
        exit(1);                                                   \
    }                                                              \
} while (0)

static void tcp_share_id(ncclUniqueId *id, int rank, int nranks,
                          const char *addr, int port) {
    if (rank == 0) {
        CHECK_NCCL(ncclGetUniqueId(id));
        int srv = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in sa = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = INADDR_ANY,
        };
        if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind");
            exit(1);
        }
        listen(srv, nranks);
        printf("[rank 0] listening on :%d for %d peer(s)\n", port, nranks - 1);
        for (int i = 0; i < nranks - 1; i++) {
            int cli = accept(srv, NULL, NULL);
            send(cli, id, sizeof(*id), 0);
            close(cli);
        }
        close(srv);
    } else {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
        };
        inet_pton(AF_INET, addr, &sa.sin_addr);
        printf("[rank %d] connecting to %s:%d\n", rank, addr, port);
        while (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            usleep(200000);
        recv(sock, id, sizeof(*id), MSG_WAITALL);
        close(sock);
    }
}

static void run_allreduce(ncclComm_t *comms, cudaStream_t *streams,
                          float **sbuf, float **rbuf,
                          size_t count, int ngpus) {
    CHECK_NCCL(ncclGroupStart());
    for (int g = 0; g < ngpus; g++)
        CHECK_NCCL(ncclAllReduce(sbuf[g], rbuf[g], count,
                                 ncclFloat, ncclSum, comms[g], streams[g]));
    CHECK_NCCL(ncclGroupEnd());
    for (int g = 0; g < ngpus; g++) {
        CHECK_CUDA(cudaSetDevice(g));
        CHECK_CUDA(cudaStreamSynchronize(streams[g]));
    }
}

int main(int argc, char **argv) {
    int rank        = atoi(getenv("RANK")        ? : "0");
    int nranks      = atoi(getenv("NRANKS")      ? : "2");
    int ngpus       = atoi(getenv("NGPUS")       ? : "8");
    int master_port = atoi(getenv("MASTER_PORT") ? : "29500");
    const char *master_addr = getenv("MASTER_ADDR") ? : "127.0.0.1";

    int total = nranks * ngpus;
    printf("rank=%d/%d  gpus=%d  total_ranks=%d  master=%s:%d\n",
           rank, nranks, ngpus, total, master_addr, master_port);

    ncclUniqueId id;
    tcp_share_id(&id, rank, nranks, master_addr, master_port);
    printf("[rank %d] NCCL ID exchanged\n", rank);

    ncclComm_t  *comms   = calloc(ngpus, sizeof(*comms));
    cudaStream_t *streams = calloc(ngpus, sizeof(*streams));

    CHECK_NCCL(ncclGroupStart());
    for (int g = 0; g < ngpus; g++) {
        CHECK_CUDA(cudaSetDevice(g));
        CHECK_CUDA(cudaStreamCreate(&streams[g]));
        CHECK_NCCL(ncclCommInitRank(&comms[g], total, id, rank * ngpus + g));
    }
    CHECK_NCCL(ncclGroupEnd());
    printf("[rank %d] %d communicators ready\n", rank, ngpus);

    size_t max_bytes = 1UL << 27; /* 128 MB */
    float **sbuf = calloc(ngpus, sizeof(float *));
    float **rbuf = calloc(ngpus, sizeof(float *));
    for (int g = 0; g < ngpus; g++) {
        CHECK_CUDA(cudaSetDevice(g));
        CHECK_CUDA(cudaMalloc((void **)&sbuf[g], max_bytes));
        CHECK_CUDA(cudaMalloc((void **)&rbuf[g], max_bytes));
        CHECK_CUDA(cudaMemset(sbuf[g], 1, max_bytes));
    }

    if (rank == 0)
        printf("[rank 0] pre-warming at %zu bytes to establish all channels...\n",
               max_bytes);
    for (int i = 0; i < 50; i++)
        run_allreduce(comms, streams, sbuf, rbuf,
                      max_bytes / sizeof(float), ngpus);
    if (rank == 0)
        printf("[rank 0] pre-warm done\n\n");

    size_t sizes[] = {
        8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
        32768, 65536, 131072, 262144, 524288, 1<<20, 1<<21, 1<<22,
        1<<23, 1<<24, 1<<25, 1<<26, 1<<27,
    };
    int nsizes = sizeof(sizes) / sizeof(sizes[0]);
    int warmup = 5, iters = 20;

    if (rank == 0)
        printf("%12s  %10s  %11s  %11s\n",
               "size(B)", "time(us)", "algbw(GB/s)", "busbw(GB/s)");

    for (int s = 0; s < nsizes; s++) {
        size_t bytes = sizes[s];
        size_t count = bytes / sizeof(float);
        if (count < 1) count = 1;

        for (int i = 0; i < warmup; i++)
            run_allreduce(comms, streams, sbuf, rbuf, count, ngpus);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < iters; i++)
            run_allreduce(comms, streams, sbuf, rbuf, count, ngpus);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        double us = ((t1.tv_sec - t0.tv_sec) * 1e6 +
                     (t1.tv_nsec - t0.tv_nsec) / 1e3) / iters;
        double algbw = bytes / us / 1e3;
        double busbw = algbw * 2.0 * (total - 1) / total;

        if (rank == 0)
            printf("%12zu  %10.1f  %11.2f  %11.2f\n",
                   bytes, us, algbw, busbw);
    }

    for (int g = 0; g < ngpus; g++) {
        CHECK_CUDA(cudaSetDevice(g));
        CHECK_CUDA(cudaFree(sbuf[g]));
        CHECK_CUDA(cudaFree(rbuf[g]));
    }
    free(sbuf);
    free(rbuf);
    for (int g = 0; g < ngpus; g++) {
        ncclCommDestroy(comms[g]);
        cudaStreamDestroy(streams[g]);
    }
    free(comms);
    free(streams);
    return 0;
}
