load("//tools:defs.bzl", "go_test")

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
        "//pkg/test/testutil",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
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

# We copy the `run_sniffer` binary here because `go:embed` can only embed
# from the current directory or subdirectories, not parents of it.
genrule(
    name = "run_sniffer_copy",
    srcs = [
        "//tools/ioctl_sniffer:run_sniffer",
    ],
    outs = ["run_sniffer_copy"],
    cmd = "cat < $(SRCS) > $@",
)

go_test(
    name = "sniffer_test",
    srcs = ["sniffer_test.go"],
    embedsrcs = [
        ":run_sniffer_copy",  # keep
    ],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "@com_github_docker_docker//api/types/mount:go_default_library",
    ],
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
