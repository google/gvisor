load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "tracereplay",
    srcs = [
        "replay.go",
        "save.go",
        "tracereplay.go",
    ],
    visibility = [
        "//tools/tracereplay:__subpackages__",
    ],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/log",
        "//pkg/sentry/seccheck/checkers/remote/server",
        "//pkg/sentry/seccheck/checkers/remote/wire",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "tracereplay_test",
    srcs = ["tracereplay_test.go"],
    data = [
        "testdata/client-0001",
    ],
    library = ":tracereplay",
    deps = [
        "//pkg/test/testutil",
    ],
)
