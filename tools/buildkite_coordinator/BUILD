load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "buildkite_coordinator",
    srcs = [
        "config.go",
        "github.go",
        "main.go",
        "secrets.go",
    ],
    # Static binary to allow running under distroless Cloud Run image
    pure = True,
    static = True,
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_google_go_github_v92//github:go_default_library",
        "@org_golang_google_api//secretmanager/v1:go_default_library",
    ],
)
