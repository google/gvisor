load("//images:defs.bzl", "docker_image")
load("//tools:defs.bzl", "go_binary", "pkg_tar")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

filegroup(
    name = "go_export_sources",
    srcs = glob(
        ["*.go"],
        exclude = ["*_test.go"],
    ),
    visibility = ["//:__pkg__"],
)

docker_image(
    name = "image",
    data = ":files",
    statements = ['ENTRYPOINT ["/webhook"]'],
    tags = [
        "local",
        "manual",
        "no-sandbox",
    ],
)

# files is the full file system of the webhook container. It is simply:
# /
# └─ webhook
pkg_tar(
    name = "files",
    srcs = [":webhook"],
    extension = "tgz",
    strip_prefix = "/webhook",
)

go_binary(
    name = "webhook",
    srcs = ["main.go"],
    features = ["fully_static_link"],
    pure = "on",
    deps = ["//webhook/pkg/cli"],
)
