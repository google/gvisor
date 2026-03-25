#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    struct ibv_device **dev_list = ibv_get_device_list(NULL);
    if (!dev_list) { fprintf(stderr, "No IB devices\n"); return 1; }

    struct ibv_context *ctx = ibv_open_device(dev_list[0]);
    if (!ctx) { fprintf(stderr, "Can't open device\n"); return 1; }
    printf("Device: %s\n", ibv_get_device_name(dev_list[0]));

    struct ibv_pd *pd = ibv_alloc_pd(ctx);
    if (!pd) { fprintf(stderr, "ibv_alloc_pd FAILED\n"); return 1; }
    printf("PD OK\n");

    /* MR - exercises existing page mirroring */
    size_t buf_size = 65536;
    void *buf = malloc(buf_size);
    memset(buf, 0x42, buf_size);
    struct ibv_mr *mr = ibv_reg_mr(pd, buf, buf_size,
        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
    if (!mr) { fprintf(stderr, "ibv_reg_mr FAILED\n"); return 1; }
    printf("MR OK: lkey=%u rkey=%u\n", mr->lkey, mr->rkey);

    /* CQ - exercises new buf_addr/db_addr mirroring */
    struct ibv_cq *cq = ibv_create_cq(ctx, 256, NULL, NULL, 0);
    if (!cq) { fprintf(stderr, "ibv_create_cq FAILED\n"); return 1; }
    printf("CQ OK: cqe=%d\n", cq->cqe);

    /* QP - exercises new buf_addr/db_addr mirroring */
    struct ibv_qp_init_attr qp_init = {
        .send_cq = cq,
        .recv_cq = cq,
        .qp_type = IBV_QPT_RC,
        .cap = {
            .max_send_wr = 16,
            .max_recv_wr = 16,
            .max_send_sge = 1,
            .max_recv_sge = 1,
        },
    };
    struct ibv_qp *qp = ibv_create_qp(pd, &qp_init);
    if (!qp) { fprintf(stderr, "ibv_create_qp FAILED\n"); return 1; }
    printf("QP OK: qp_num=%u\n", qp->qp_num);

    /* Transition QP to INIT state */
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = 1;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
    int ret = ibv_modify_qp(qp, &attr,
        IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
    if (ret) { fprintf(stderr, "ibv_modify_qp(INIT) FAILED: %d\n", ret); return 1; }
    printf("QP->INIT OK\n");

    /* Cleanup */
    ibv_destroy_qp(qp);
    printf("QP destroyed\n");
    ibv_destroy_cq(cq);
    printf("CQ destroyed\n");
    ibv_dereg_mr(mr);
    printf("MR deregistered\n");
    ibv_dealloc_pd(pd);
    ibv_close_device(ctx);
    ibv_free_device_list(dev_list);
    free(buf);
    printf("ALL PASSED\n");
    return 0;
}
