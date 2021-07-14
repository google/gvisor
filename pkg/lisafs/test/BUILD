load("//tools:defs.bzl", "go_library")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_library(
    name = "test",
    testonly = 1,
    srcs = ["test.go"],
    marshal = True,
    visibility = ["//pkg/lisafs:__subpackages__"],
    deps = ["//pkg/marshal/primitive"],
)
