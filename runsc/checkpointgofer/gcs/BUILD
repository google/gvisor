load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "gcs",
    srcs = [
        "errors.go",
        "gcs.go",
        "parallelwriter.go",
        "reader.go",
        "writer.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/log",
        "//pkg/sentry/memmap",
        "//pkg/sentry/state/checkpointfiles",
        "//pkg/sentry/state/stateio",
        "//pkg/sync",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_google_cloud_go_auth//credentials:go_default_library",
        "@com_google_cloud_go_auth_oauth2adapt//:go_default_library",
        "@com_google_cloud_go_storage//:go_default_library",
        "@org_golang_google_api//googleapi:go_default_library",
        "@org_golang_google_api//option:go_default_library",
        "@org_golang_x_oauth2//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "gcs_test",
    size = "small",
    srcs = ["parallelwriter_test.go"],
    library = ":gcs",
    deps = [
        "//pkg/sentry/state/stateio",
        "@com_google_cloud_go_storage//:go_default_library",
        "@org_golang_google_api//option:go_default_library",
    ],
)
