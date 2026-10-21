load("//images:defs.bzl", "docker_image")
load("//tools:defs.bzl", "go_binary", "pkg_tar")

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
        "main.go",
        "secrets.go",
    ],
    # Static binary, since the container image contains nothing else.
    pure = True,
    static = True,
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/cleanup",
        "//tools/buildkite_coordinator/buildkite",
        "@com_github_google_go_github_v84//github:go_default_library",
        "@com_github_googleapis_gax_go_v2//:go_default_library",
        "@com_google_cloud_go_compute_metadata//:go_default_library",
        "@org_golang_google_api//compute/v1:go_default_library",
        "@org_golang_google_api//idtoken:go_default_library",
        "@org_golang_google_api//secretmanager/v1:go_default_library",
        "@org_golang_x_crypto_x509roots_fallback//:go_default_library",
    ],
)

pkg_tar(
    name = "files",
    srcs = [":buildkite_coordinator"],
    extension = "tgz",
)

docker_image(
    name = "image",
    data = ":files",
    statements = [
        "EXPOSE 8080/tcp",
        "USER 65532:65532",
        'ENTRYPOINT ["/buildkite_coordinator"]',
    ],
    tags = [
        "local",
        "manual",
        "no-sandbox",
    ],
)
