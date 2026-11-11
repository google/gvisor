load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "sr_test",
    srcs = ["sr_test.go"],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    tags = [
        "manual",
        "noguitar",
        "notap",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)
