load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "image_test",
    size = "large",
    srcs = [
        "image_test.go",
    ],
    data = [
        "latin10k.txt",
        "mysql.sql",
        "ruby.rb",
        "ruby.sh",
        # runsc is needed to invalidate the bazel cache in case of any code changes.
        "//runsc",
    ],
    library = ":image",
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        "manual",
        "local",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "@com_github_docker_docker//api/types/mount:go_default_library",
        "@in_gopkg_yaml_v3//:go_default_library",
    ],
)

go_library(
    name = "image",
    srcs = ["image.go"],
)
