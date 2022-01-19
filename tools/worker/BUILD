load("//tools:defs.bzl", "bazel_worker_proto", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

# For Google-tooling.
# @unused
glaze_ignore = [
    "worker.go",
]

go_template_instance(
    name = "lru_list",
    out = "lru_list.go",
    package = "worker",
    prefix = "lru",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*cacheEntry",
        "Linker": "*cacheEntry",
    },
)

go_template_instance(
    name = "cache_list",
    out = "cache_list.go",
    package = "worker",
    prefix = "caches",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Cache",
        "Linker": "*Cache",
    },
)

go_library(
    name = "worker",
    srcs = [
        "worker.go",
        ":cache_list",
        ":lru_list",
    ],
    visibility = ["//tools:__subpackages__"],
    deps = [
        bazel_worker_proto,
        "//runsc/flag",
        "@org_golang_google_protobuf//encoding/protowire:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
