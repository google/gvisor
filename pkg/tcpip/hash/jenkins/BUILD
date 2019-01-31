load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "jenkins",
    srcs = ["jenkins.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/hash/jenkins",
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
