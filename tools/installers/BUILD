# Installers for use by top-level scripts.

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
        "//shim:containerd-shim-runsc-v1",
    ],
)
