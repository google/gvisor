load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "fd_refs",
    out = "fd_refs.go",
    package = "fsgofer",
    prefix = "fdLisa",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "fdLisa",
    },
)

go_library(
    name = "fsgofer",
    srcs = [
        "fd_refs.go",
        "fsgofer.go",
        "fsgofer_amd64_unsafe.go",
        "fsgofer_arm64_unsafe.go",
        "fsgofer_unsafe.go",
        "lisafs.go",
        "lisafs_fd.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/fd",
        "//pkg/lisafs",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/p9",
        "//pkg/refsvfs2",
        "//pkg/sync",
        "//pkg/syserr",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fsgofer_test",
    size = "small",
    srcs = ["fsgofer_test.go"],
    library = ":fsgofer",
    deps = [
        "//pkg/fd",
        "//pkg/log",
        "//pkg/p9",
        "//pkg/test/testutil",
        "//runsc/specutils",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "lisafs_test",
    size = "small",
    srcs = ["lisafs_test.go"],
    deps = [
        ":fsgofer",
        "//pkg/abi/linux",
        "//pkg/lisafs",
        "//pkg/log",
        "//pkg/marshal/primitive",
        "//pkg/unet",
        "//runsc/specutils",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
