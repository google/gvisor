load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "metadata",
    srcs = ["metadata.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/pgalloc/metadata",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/pgalloc:pgalloc_metadata_go_proto",
        "//pkg/state",
        "//pkg/state/wire",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)
