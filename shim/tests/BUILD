load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "shim_test",
    srcs = ["shim_test.go"],
    deps = [
        "//shim/shimutils",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
    ],
)
