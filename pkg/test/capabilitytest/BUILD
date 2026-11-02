load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "capabilitytest",
    testonly = 1,
    srcs = ["capabilitytest.go"],
    importpath = "gvisor.dev/gvisor/pkg/test/capabilitytest",
    visibility = ["//:sandbox"],
    deps = ["@com_github_moby_sys_capability//:go_default_library"],
)
