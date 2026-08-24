load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "checkpoint",
    srcs = [
        "checkpoint.go",
        "filestore_snapshot.go",
    ],
    visibility = ["//pkg/sentry:internal"],
)
