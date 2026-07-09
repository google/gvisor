load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "rdma",
    srcs = [
        "ib_user_ioctl_cmds.go",
        "ib_user_ioctl_verbs.go",
        "ib_user_mad.go",
        "ib_user_sa.go",
        "ib_user_verbs.go",
        "irdma.go",
        "rdma.go",
        "rdma_user_cm.go",
        "rdma_user_ioctl.go",
    ],
    hostlayout = True,
    marshal = True,
    visibility = [
        "//pkg/sentry:internal",
        "//tools:__subpackages__",
    ],
    deps = ["//pkg/abi/linux"],
)
