"""Generics tests."""

load("@bazel_skylib//rules:native_binary.bzl", "native_test")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

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
    generated = name + "_output.go"
    go_template_instance(
        name = name + "_output",
        template = ":" + name + "_template",
        out = generated,
        types = types,
        consts = consts,
        **kwargs
    )
    native_test(
        name = name + "_test",
        src = "//tools/go_generics/tests:compare",
        args = [
            "$(rootpath %s)" % output,
            "$(rootpath %s)" % generated,
        ],
        data = [generated, output],
    )
