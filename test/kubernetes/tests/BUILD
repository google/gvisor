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
    library = ":hello",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = ["//test/kubernetes/k8sctx/kubectlctx"],
)
