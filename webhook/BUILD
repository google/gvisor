load("//images:defs.bzl", "docker_image")
load("//tools:defs.bzl", "go_binary", "pkg_tar")

package(licenses = ["notice"])

docker_image(
    name = "webhook_image",
    data = ":files",
    statements = ['ENTRYPOINT ["/webhook"]'],
)

# files is the full file system of the webhook container. It is simply:
# /
# └─ webhook
pkg_tar(
    name = "files",
    srcs = [":webhook"],
    extension = "tgz",
    strip_prefix = "/third_party/gvisor/webhook",
)

go_binary(
    name = "webhook",
    srcs = ["main.go"],
    pure = "on",
    static = "on",
    deps = ["//webhook/pkg/cli"],
)
