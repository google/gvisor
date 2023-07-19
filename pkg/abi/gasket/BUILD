load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "gasket",
    srcs = [
        "gasket.go",
    ],
    marshal = True,
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/abi/linux"],
)
