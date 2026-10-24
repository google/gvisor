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
        "impersonate.go",
        "main.go",
        "ratelimit.go",
        "secrets.go",
        "storage.go",
        "timeout.go",
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

genrule(
    name = "ca_certificates",
    srcs = ["@ca_certificates_files//:mozilla"],
    outs = ["ca-certificates.crt"],
    cmd = "cat $(SRCS) > $@",
)

pkg_tar(
    name = "certs",
    srcs = [":ca_certificates"],
    mode = "0644",
    package_dir = "/etc/ssl/certs",
)

pkg_tar(
    name = "files",
    srcs = [":buildkite_coordinator"],
    extension = "tgz",
    deps = [":certs"],
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
