load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "docprocessor",
    srcs = ["docprocessor.go"],
    visibility = ["//examples/sandboxexec/go:__subpackages__"],
    deps = ["//sandboxexec/sandbox"],
)

go_test(
    name = "docprocessor_test",
    srcs = ["docprocessor_test.go"],
    data = ["//:release"],
    library = ":docprocessor",
    tags = ["nogotsan"],
    deps = ["//pkg/test/testutil"],
)
