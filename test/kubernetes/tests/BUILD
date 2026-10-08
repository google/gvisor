load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "hello",
    testonly = True,
    srcs = ["hello.go"],
    nogo = False,
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
    ],
)

go_test(
    name = "hello_test",
    srcs = ["hello_test.go"],
    embed = [":hello"],
    local = True,
    nogo = False,
    tags = [
        "noguitar",
        "notap",
    ],
    deps = ["//test/kubernetes/k8sctx/kubectlctx"],
)

go_library(
    name = "driver",
    testonly = True,
    srcs = ["driver_version.go"],
    deps = [
        "//test/gpu:gpu_driver_versions_go_proto",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@org_golang_google_protobuf//encoding/prototext:go_default_library",
    ],
)

go_test(
    name = "driver_test",
    srcs = ["driver_version_test.go"],
    embed = [":driver"],
    local = True,
    tags = [
        "noguitar",
        "notap",
    ],
    deps = ["//test/kubernetes/k8sctx/kubectlctx"],
)

go_library(
    name = "cudatest",
    testonly = True,
    srcs = ["cuda_test_lib.go"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/kubernetes",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
    ],
)

go_test(
    name = "cuda_test",
    srcs = ["cuda_test.go"],
    embed = [":cudatest"],
    local = True,
    tags = [
        "noguitar",
        "notap",
    ],
    deps = ["//test/kubernetes/k8sctx/kubectlctx"],
)
