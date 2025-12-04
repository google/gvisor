load("//tools:defs.bzl", "go_library", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

proto_library(
    name = "api",
    srcs = [
        "runtimeoptions.proto",
    ],
)

go_library(
    name = "runtimeoptions",
    srcs = [
        "runtimeoptions.go",
        "runtimeoptions_cri.go",
    ],
    visibility = [
        "//pkg/shim:__subpackages__",
    ],
    deps = ["@com_github_gogo_protobuf//proto:go_default_library"],
)
