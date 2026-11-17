load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_template_instance(
    name = "gofer_client_refs",
    out = "gofer_client_refs.go",
    package = "devutil",
    prefix = "goferClient",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "GoferClient",
    },
)

go_library(
    name = "devutil",
    srcs = [
        "context.go",
        "devutil.go",
        "gofer_client_refs.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/devutil",
    visibility = ["//visibility:public"],
    # Includes imports from generated gofer_client_refs.go.
    deps = [
        "//pkg/atomicbitops",  # keep
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/fsutil",
        "//pkg/lisafs",
        "//pkg/log",
        "//pkg/refs",  # keep
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
