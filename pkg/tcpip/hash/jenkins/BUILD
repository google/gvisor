load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "jenkins",
    srcs = ["jenkins.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/hash/jenkins",
    visibility = [
        "//visibility:public",
    ],
)

go_test(
    name = "jenkins_test",
    size = "small",
    srcs = [
        "jenkins_test.go",
    ],
    embed = [":jenkins"],
)
