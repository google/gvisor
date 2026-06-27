load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "shimutils",
    testonly = True,
    srcs = ["shimutils.go"],
    data = [
        "//runsc",
        "//shim:containerd-shim-runsc-v1",
    ],
    visibility = ["//shim:__subpackages__"],
    deps = [
        "//pkg/shim/v1/runtimeoptions",
        "//pkg/test/testutil",
        "//runsc/specutils",
        "@com_github_burntsushi_toml//:go_default_library",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_containerd_api//services/ttrpc/events/v1:go_default_library",
        "@com_github_containerd_ttrpc//:go_default_library",
        "@com_github_containerd_typeurl_v2//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_google_protobuf//types/known/anypb:go_default_library",
        "@org_golang_google_protobuf//types/known/emptypb:go_default_library",
    ],
)
