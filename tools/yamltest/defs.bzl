"""Tools for testing YAML files against schemas."""

load("@bazel_skylib//rules:native_binary.bzl", "native_test")

def _yaml_test_options_impl(ctx):
    # Resolve select() on the flags and schema before Bazel expands the test args.
    return [
        DefaultInfo(files = depset([ctx.file.schema])),
        platform_common.TemplateVariableInfo({
            "YAMLTEST_STRICT": "true" if ctx.attr.strict else "false",
            "YAMLTEST_DISALLOW_COMMENTS": "true" if ctx.attr.disallow_comments else "false",
        }),
    ]

_yaml_test_options = rule(
    implementation = _yaml_test_options_impl,
    attrs = {
        "schema": attr.label(allow_single_file = True, mandatory = True),
        "strict": attr.bool(mandatory = True),
        "disallow_comments": attr.bool(mandatory = True),
    },
)

def yaml_test(
        name,
        srcs,
        schema,
        strict = True,
        disallow_comments = False,
        *,
        args = [],
        data = [],
        toolchains = [],
        **kwargs):
    """Tests YAML files against a JSON schema.

    Args:
        name: Test target name.
        srcs: Input YAML files or filegroups.
        schema: JSON schema file.
        strict: Whether to use strict mode for YAML decoding.
        disallow_comments: Whether to disallow comments in the YAML files.
        args: Additional arguments passed to the validator after the source files.
        data: Additional files available to the test at runtime.
        toolchains: Additional toolchains providing variables for test arguments.
        **kwargs: Additional test attributes.
    """
    sources = name + "_srcs"
    options = name + "_options"
    native.filegroup(
        name = sources,
        srcs = srcs,
        tags = ["manual"],
        testonly = True,
        visibility = ["//visibility:private"],
    )
    _yaml_test_options(
        name = options,
        schema = schema,
        strict = strict,
        disallow_comments = disallow_comments,
        tags = ["manual"],
        testonly = True,
        visibility = ["//visibility:private"],
    )
    native_test(
        name = name,
        src = Label("//tools/yamltest:yamltest"),
        out = name,
        args = [
            "-schema",
            "$(rootpath :%s)" % options,
            "-strict=$(YAMLTEST_STRICT)",
            "-disallow_comments=$(YAMLTEST_DISALLOW_COMMENTS)",
            "--",
            "$(rootpaths :%s)" % sources,
        ] + args,
        data = [":" + options, ":" + sources] + data,
        toolchains = [":" + options] + toolchains,
        **kwargs
    )
