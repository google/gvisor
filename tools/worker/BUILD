load("//tools:defs.bzl", "bazel_worker_proto", "go_library")

package(licenses = ["notice"])

# For Google-tooling.
# @unused
glaze_ignore = [
    "worker.go",
]

go_library(
    name = "worker",
    srcs = ["worker.go"],
    visibility = ["//tools:__subpackages__"],
    deps = [
        bazel_worker_proto,
        "@org_golang_google_protobuf//encoding/protowire:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
