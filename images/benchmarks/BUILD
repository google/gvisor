load("@bazel_skylib//rules:write_file.bzl", "write_file")
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

_HTTP_PAYLOAD_SIZES = [
    1,
    10,
    100,
    1024,
    10240,
]

[
    write_file(
        name = "http_payload_%d" % size,
        out = "latin%dk.txt" % size,
        content = ["\000" * (size * 1024)],
    )
    for size in _HTTP_PAYLOAD_SIZES
]

image_layer(
    name = "http_payload_layer",
    srcs = {
        "/local/latin%dk.txt" % size: ":http_payload_%d" % size
        for size in _HTTP_PAYLOAD_SIZES
    },
    default_metadata = file_metadata(mode = "0644"),
)

image_layer(
    name = "httpd_config_layer",
    srcs = {"/usr/local/apache2/conf/httpd.conf": "httpd/httpd.conf"},
    default_metadata = file_metadata(mode = "0644"),
    # The existing benchmark invokes the distribution's apache2 command.
    symlinks = {"/usr/local/bin/apache2": "/usr/local/apache2/bin/httpd"},
)

image_manifest(
    name = "httpd",
    base = "@benchmark_httpd",
    layers = [
        ":http_payload_layer",
        ":httpd_config_layer",
    ],
    tags = ["manual"],
)

image_outputs(
    name = "httpd",
    image = ":httpd",
    image_name = "benchmarks/httpd",
)
