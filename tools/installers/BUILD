# Installers for use by the tools/vm_test rules.

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

filegroup(
    name = "runsc",
    srcs = ["//runsc"],
)

sh_binary(
    name = "head",
    srcs = ["head.sh"],
    data = [":runsc"],
)

sh_binary(
    name = "master",
    srcs = ["master.sh"],
)

sh_binary(
    name = "shim",
    srcs = ["shim.sh"],
)
