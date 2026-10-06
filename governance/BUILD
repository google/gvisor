load("//governance/tools/maintainers:defs.bzl", "governance_files")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

exports_files(
    ["licensing.yaml"],
    visibility = ["//tools/licensecheck:__pkg__"],
)

governance_files(name = "generated")
