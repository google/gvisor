load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "jenkins",
    srcs = ["jenkins.go"],
    visibility = ["//visibility:public"],
)

go_test(
    name = "jenkins_test",
    size = "small",
    srcs = [
        "jenkins_test.go",
    ],
    library = ":jenkins",
)
