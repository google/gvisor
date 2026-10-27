load("@rules_img//img:image.bzl", "image_manifest")
load("@rules_img//img:layer.bzl", "file_metadata", "image_layer")
load("//images:img.bzl", "image_outputs")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

filegroup(
    name = "sources",
    srcs = glob(["**"]),
    visibility = ["//images:__pkg__"],
)

# Preserve the complete release layout, including future additions.
image_layer(
    name = "payload",
    srcs = {"/opt/gvisor/": "//:release"},
    default_metadata = file_metadata(mode = "0755"),
)

image_layer(
    name = "agent",
    srcs = {"/usr/local/bin/nodeinstaller": "//tools/gvisor_k8s_tool/cmd/nodeinstaller"},
    default_metadata = file_metadata(mode = "0755"),
    include_runfiles = False,
)

image_manifest(
    name = "gvisor_installer",
    base = "@gvisor_installer_base",
    entrypoint = ["/usr/local/bin/nodeinstaller"],
    layers = [
        ":payload",
        ":agent",
    ],
    tags = ["manual"],
    visibility = ["//visibility:public"],
)

image_outputs(
    name = "gvisor_installer",
    image = ":gvisor_installer",
    image_name = "gvisor-installer",
)
