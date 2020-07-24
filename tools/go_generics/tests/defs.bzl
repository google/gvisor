"""Generics tests."""

load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

def _go_generics_test_impl(ctx):
    runner = ctx.actions.declare_file(ctx.label.name)
    runner_content = "\n".join([
        "#!/bin/bash",
        "exec diff --ignore-blank-lines --ignore-matching-lines=^[[:space:]]*// %s %s" % (
            ctx.files.template_output[0].short_path,
            ctx.files.expected_output[0].short_path,
        ),
        "",
    ])
    ctx.actions.write(runner, runner_content, is_executable = True)
    return [DefaultInfo(
        executable = runner,
        runfiles = ctx.runfiles(
            files = ctx.files.template_output + ctx.files.expected_output,
            collect_default = True,
            collect_data = True,
        ),
    )]

_go_generics_test = rule(
    implementation = _go_generics_test_impl,
    attrs = {
        "template_output": attr.label(mandatory = True, allow_single_file = True),
        "expected_output": attr.label(mandatory = True, allow_single_file = True),
    },
    test = True,
)

def go_generics_test(name, inputs, output, types = None, consts = None, **kwargs):
    """Instantiates a generics test.

    Args:
        name: the name of the test.
        inputs: all the input files.
        output: the output files.
        types: the template types (dictionary).
        consts: the template consts (dictionary).
        **kwargs: additional arguments for the template_instance.
    """
    if types == None:
        types = dict()
    if consts == None:
        consts = dict()
    go_template(
        name = name + "_template",
        srcs = inputs,
        types = types.keys(),
        consts = consts.keys(),
    )
    go_template_instance(
        name = name + "_output",
        template = ":" + name + "_template",
        out = name + "_output.go",
        types = types,
        consts = consts,
        **kwargs
    )
    _go_generics_test(
        name = name + "_test",
        template_output = name + "_output.go",
        expected_output = output,
    )
