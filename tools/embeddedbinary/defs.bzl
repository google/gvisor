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
        compress = True,
        extract_to_disk = True,
        visibility = None):
    """Embed a binary and generate a go_library target that can execute it.

    Args:
        name: The name of the go_library rule.
        binary: Binary BUILD target that should be embedded.
        binary_name: The name (i.e. typical argv[0]) of the binary being
          embedded, defaults to `name`.
        out: Output filename of the go_library rule, defaults to `name + ".go"`.
        go_package_name: Package name of the go_library, defaults to `name`.
        compress: If True, embed the binary in compressed form in `-c opt`
          builds, but in uncompressed form in non-`-c opt` builds (to reduce
          build time). If False, embed the binary in uncompressed form in all
          builds.
        extract_to_disk: If True, try to extract the binary to os.TempDir(). If
          False, or when os.TempDir() is unavailable or not executable, extract
          the binary to memory. Enabling extract_to_disk reduces memory usage
          but increases the time taken to execute the binary.
        visibility: Visibility of the go_library rule.
    """
    if binary_name == None:
        binary_name = name
    if out == None:
        out = name + ".go"
    if go_package_name == None:
        go_package_name = name

    uncompressed_binary = binary_name + ".bin"
    native.genrule(
        name = name + "_noflate",
        outs = [uncompressed_binary],
        cmd = "cat < $(SRCS) > $(OUTS)",
        srcs = [binary],
    )
    lib_substrs_uncompressed = {
        "//go:embed embedded.bin.flate": "//go:embed %s" % (uncompressed_binary,),
        "flate.NewReader": "io.Reader",
    }

    if compress:
        compressed_binary = binary_name + ".flate"
        native.genrule(
            name = name + "_flate",
            outs = [compressed_binary],
            cmd = "$(location %s) < $(SRCS) > $(OUTS)" % (_FLATECOMPRESS,),
            srcs = [binary],
            tools = [_FLATECOMPRESS],
        )
        lib_substrs_extra = select({
            "//tools/embeddedbinary:compilation_mode_opt": {
                "//go:embed embedded.bin.flate": "//go:embed %s" % (compressed_binary,),
            },
            "//conditions:default": lib_substrs_uncompressed,
        })
        embedsrcs = select({
            "//tools/embeddedbinary:compilation_mode_opt": [compressed_binary],
            "//conditions:default": [uncompressed_binary],
        })
    else:
        lib_substrs_extra = lib_substrs_uncompressed
        embedsrcs = [uncompressed_binary]

    go_template_instance(
        name = name + "_lib",
        template = _EMBEDDED_BINARY_TEMPLATE,
        package = go_package_name,
        out = out,
        substrs = {
            "embedded.bin.name": binary_name,
            "extractToDisk": str(extract_to_disk).lower(),
        } | lib_substrs_extra,
    )
    go_library(
        name = name,
        srcs = [out],
        embedsrcs = embedsrcs,
        deps = ["@org_golang_x_sys//unix:go_default_library"],
        visibility = visibility,
    )
