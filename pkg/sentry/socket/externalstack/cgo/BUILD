package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "cgo",
    srcs = [
        "socket_unsafe.go",
        "stack_unsafe.go",
    ],
    cgo = True,
    visibility = ["//visibility:public"],
)
