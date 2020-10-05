# Installers for use by the tools/vm_test rules.

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

sh_binary(
    name = "head",
    srcs = ["head.sh"],
    data = [
        "//runsc",
    ],
)

sh_binary(
    name = "images",
    srcs = ["images.sh"],
    data = [
        "//images",
    ],
)

sh_binary(
    name = "master",
    srcs = ["master.sh"],
)

sh_binary(
    name = "containerd",
    srcs = ["containerd.sh"],
)

sh_binary(
    name = "shim",
    srcs = ["shim.sh"],
    data = [
        "//shim/v1:gvisor-containerd-shim",
        "//shim/v2:containerd-shim-runsc-v1",
    ],
)
