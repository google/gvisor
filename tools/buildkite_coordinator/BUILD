load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "buildkite_coordinator",
    srcs = [
        "config.go",
        "main.go",
        "secrets.go",
    ],
    # Static binary to allow running under distroless Cloud Run image
    pure = True,
    static = True,
    visibility = ["//visibility:public"],
    deps = [
        "@org_golang_google_api//secretmanager/v1:go_default_library",
    ],
)
