load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "smoke_test",
    srcs = ["smoke_test.go"],
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/test/dockerutil"],
)

go_test(
    name = "pytorch_test",
    srcs = ["pytorch_test.go"],
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/test/dockerutil"],
)

go_test(
    name = "textgen_test",
    srcs = ["textgen_test.go"],
    embedsrcs = ["gvisor.png"],
    tags = [
        "local",
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
    tags = [
        "local",
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
    name = "imagegen_test",
    srcs = ["imagegen_test.go"],
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = ["//test/gpu/stablediffusion"],
)
