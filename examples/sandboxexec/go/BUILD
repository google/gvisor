load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "doc_processor",
    srcs = ["doc_processor.go"],
    deps = [
        "//sandboxexec/sandbox",
    ],
)

go_test(
    name = "doc_processor_test",
    srcs = ["doc_processor_test.go"],
    data = ["//:release"],
    library = ":doc_processor",
    tags = ["nogotsan"],
    deps = ["//pkg/test/testutil"],
)
