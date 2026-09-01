load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "vllm_test",
    srcs = ["vllm_test.go"],
    data = [
        "//:release",
    ],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/tpu/vllm",
    ],
)
