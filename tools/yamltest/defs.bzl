"""Tools for testing yaml files against schemas."""

def _yaml_test_impl(ctx):
    """Implementation for yaml_test."""
    runner = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.write(runner, "\n".join([
        "#!/bin/bash",
        "set -euo pipefail",
        "%s -schema=%s -strict=%s -- %s" % (
            ctx.files._tool[0].short_path,
            ctx.files.schema[0].short_path,
            "true" if ctx.attr.strict else "false",
            " ".join([f.short_path for f in ctx.files.srcs]),
        ),
    ]), is_executable = True)
    return [DefaultInfo(
        runfiles = ctx.runfiles(files = ctx.files._tool + ctx.files.schema + ctx.files.srcs),
        executable = runner,
    )]

yaml_test = rule(
    implementation = _yaml_test_impl,
    doc = "Tests a yaml file against a schema.",
    attrs = {
        "srcs": attr.label_list(
            doc = "The input yaml files.",
            mandatory = True,
            allow_files = True,
        ),
        "schema": attr.label(
            doc = "The schema file in JSON schema format.",
            allow_single_file = True,
            mandatory = True,
        ),
        "strict": attr.bool(
            doc = "Whether to use strict mode for YAML decoding.",
            mandatory = False,
            default = True,
        ),
        "_tool": attr.label(
            executable = True,
            cfg = "exec",
            default = Label("//tools/yamltest:yamltest"),
        ),
    },
    test = True,
)
