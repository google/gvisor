load("//tools:defs.bzl", "go_binary")
load("//website:defs.bzl", "doc")

package(licenses = ["notice"])

go_binary(
    name = "gvisor-containerd-shim",
    srcs = [
        "config.go",
        "main.go",
    ],
    pure = True,
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/shim/runsc",
        "//pkg/shim/v1/shim",
        "//pkg/shim/v2",
        "@com_github_burntsushi_toml//:go_default_library",
        "@com_github_containerd_containerd//events:go_default_library",
        "@com_github_containerd_containerd//namespaces:go_default_library",
        "@com_github_containerd_containerd//runtime/v1/linux/proc:go_default_library",
        "@com_github_containerd_containerd//runtime/v1/shim:go_default_library",
        "@com_github_containerd_containerd//runtime/v1/shim/v1:go_default_library",
        "@com_github_containerd_containerd//runtime/v2/shim:go_default_library",
        "@com_github_containerd_ttrpc//:go_default_library",
        "@com_github_containerd_typeurl//:go_default_library",
        "@com_github_gogo_protobuf//types:go_default_library",
        "@com_github_opencontainers_runc//libcontainer/system:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

doc(
    name = "doc",
    src = "README.md",
    category = "User Guide",
    permalink = "/docs/user_guide/gvisor-containerd-shim/",
    subcategory = "Advanced",
    visibility = ["//website:__pkg__"],
    weight = "93",
)
