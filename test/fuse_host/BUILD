load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "fusehost",
    srcs = ["server.go"],
    deps = [
        "//pkg/abi/linux",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fusehost_test",
    srcs = ["fuse_host_test.go"],
    data = [
        "//runsc",
        "//test/fuse_host/workload",
    ],
    library = ":fusehost",
    deps = [
        "//pkg/test/testutil",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
