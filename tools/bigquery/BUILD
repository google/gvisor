load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "bigquery",
    testonly = 1,
    srcs = ["bigquery.go"],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "@com_google_cloud_go_bigquery//:go_default_library",
        "@org_golang_google_api//option:go_default_library",
    ],
)
