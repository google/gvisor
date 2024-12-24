load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "autok8sctx",
    testonly = True,
    srcs = ["kubectlctx.go"],
    nogo = False,
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//runsc/flag",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "//tools/gvisor_k8s_tool/provider/kubectl",
    ],
)
