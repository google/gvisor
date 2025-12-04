load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "runtimeoptions_test",
    size = "small",
    srcs = ["runtimeoptions_test.go"],
    deps = [
        "//pkg/shim/runtimeoptions",
        "@com_github_containerd_containerd_api//runtime/task/v3:go_default_library",
        "@com_github_containerd_typeurl_v2//:go_default_library",
        "@com_github_gogo_protobuf//proto:go_default_library",
    ],
)
