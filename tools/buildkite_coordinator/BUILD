load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "buildkite_coordinator",
    srcs = [
        "buildkite.go",
        "config.go",
        "github.go",
        "identity.go",
        "impersonate.go",
        "main.go",
        "ratelimit.go",
        "secrets.go",
        "storage.go",
        "timeout.go",
    ],
    # Static binary to allow running on any VM image
    pure = True,
    static = True,
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/cleanup",
        "//tools/buildkite_coordinator/buildkite",
        "@com_github_google_go_github_v84//github:go_default_library",
        "@com_github_googleapis_gax_go_v2//:go_default_library",
        "@com_google_cloud_go_auth//:go_default_library",
        "@com_google_cloud_go_auth//credentials:go_default_library",
        "@com_google_cloud_go_auth//credentials/downscope:go_default_library",
        "@com_google_cloud_go_auth//credentials/impersonate:go_default_library",
        "@com_google_cloud_go_compute_metadata//:go_default_library",
        "@com_google_cloud_go_firestore//:go_default_library",
        "@org_golang_google_api//compute/v1:go_default_library",
        "@org_golang_google_api//googleapi:go_default_library",
        "@org_golang_google_api//idtoken:go_default_library",
        "@org_golang_google_api//secretmanager/v1:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
    ],
)
