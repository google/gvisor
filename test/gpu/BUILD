load("//tools:defs.bzl", "go_test", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "smoke_test",
    srcs = ["smoke_test.go"],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/test/dockerutil"],
)

go_test(
    name = "pytorch_test",
    srcs = ["pytorch_test.go"],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/test/dockerutil"],
)

go_test(
    name = "textgen_test",
    srcs = ["textgen_test.go"],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    embedsrcs = ["gvisor.png"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "//test/gpu/ollama",
    ],
)

go_test(
    name = "sr_test",
    srcs = ["sr_test.go"],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/context",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)

go_test(
    name = "cuda_test",
    timeout = "eternal",  # YES_I_REALLY_NEED_AN_ETERNAL_TEST
    srcs = ["cuda_test.go"],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/gpu/cuda",
    ],
)

go_test(
    name = "cuda_12_8_test",
    timeout = "eternal",  # YES_I_REALLY_NEED_AN_ETERNAL_TEST
    srcs = ["cuda_12_8_test.go"],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/gpu/cuda",
    ],
)

go_test(
    name = "ffmpeg_test",
    srcs = ["ffmpeg_test.go"],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/test/dockerutil"],
)

go_test(
    name = "imagegen_test",
    srcs = ["imagegen_test.go"],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = ["//test/gpu/stablediffusion"],
)

go_test(
    name = "sniffer_test",
    srcs = ["sniffer_test.go"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/test/dockerutil"],
)

go_test(
    name = "nccl_test",
    srcs = ["nccl_test.go"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/test/dockerutil"],
)

proto_library(
    name = "gpu_driver_versions",
    srcs = ["gpu_driver_versions.proto"],
)

go_test(
    name = "cos_gpu_compatibility_test",
    srcs = ["cos_gpu_compatibility_test.go"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    deps = [
        ":gpu_driver_versions_go_proto",
        "//pkg/sentry/devices/nvproxy",
        "@org_golang_google_protobuf//encoding/prototext:go_default_library",
    ],
)
