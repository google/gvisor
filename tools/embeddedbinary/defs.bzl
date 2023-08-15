"""BUILD rule for embedded binaries."""

load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

_EMBEDDED_BINARY_TEMPLATE = "//tools/embeddedbinary:embeddedbinary_template"
_FLATECOMPRESS = "//tools/embeddedbinary:flatecompress"

def embedded_binary_go_library(
        name,
        binary,
        binary_name = None,
        out = None,
        go_package_name = None,
        visibility = None):
    """Embed a binary and generate a go_library target that can execute it.

    The binary will be compressed, and needs temporary space to be available
    when executing.

    Args:
        name: The name of the go_library rule.
        binary: Binary BUILD target that should be embedded.
        binary_name: The name (i.e. typical argv[0]) of the binary being
          embedded, defaults to `name`.
        out: Output filename of the go_library rule, defaults to `name + ".go"`.
        go_package_name: Package name of the go_library, defaults to `name`.
        visibility: Visibility of the go_library rule.
    """
    if binary_name == None:
        binary_name = name
    if out == None:
        out = name + ".go"
    if go_package_name == None:
        go_package_name = name
    compressed_binary = binary_name + ".flate"
    native.genrule(
        name = name + "_flate",
        outs = [compressed_binary],
        cmd = "$(location %s) < $(SRCS) > $(OUTS)" % (_FLATECOMPRESS,),
        srcs = [binary],
        tools = [_FLATECOMPRESS],
    )
    go_template_instance(
        name = name + "_lib",
        template = _EMBEDDED_BINARY_TEMPLATE,
        package = go_package_name,
        out = out,
        substrs = {
            "embedded.bin.name": binary_name,
            "//go:embed embedded.bin.flate": "//go:embed %s" % (compressed_binary,),
        },
    )
    go_library(
        name = name,
        srcs = [out],
        embedsrcs = [compressed_binary],
        deps = ["@org_golang_x_sys//unix:go_default_library"],
        visibility = visibility,
    )
