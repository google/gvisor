load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "xmlreport",
    srcs = ["xml.go"],
    importpath = "gvisor.dev/gvisor/test/runner/xmlreport",
    visibility = ["//:sandbox"],
)

go_test(
    name = "xmlreport_test",
    size = "small",
    srcs = ["xml_test.go"],
    embed = [":xmlreport"],
)
