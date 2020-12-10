"""Generics support via go_generics.

A Go template is similar to a go library, except that it has certain types that
can be replaced before usage. For example, one could define a templatized List
struct, whose elements are of type T, then instantiate that template for
T=segment, where "segment" is the concrete type.
"""

TemplateInfo = provider(
    "Information about a go_generics template.",
    fields = {
        "unsafe": "whether the template requires unsafe code",
        "types": "required types",
        "opt_types": "optional types",
        "consts": "required consts",
        "opt_consts": "optional consts",
        "deps": "package dependencies",
        "template": "merged template source file",
    },
)

def _go_template_impl(ctx):
    srcs = ctx.files.srcs
    template = ctx.actions.declare_file(ctx.label.name + "_template.go")
    args = ["-o=%s" % template.path] + [f.path for f in srcs]

    ctx.actions.run(
        inputs = srcs,
        outputs = [template],
        mnemonic = "GoGenericsTemplate",
        progress_message = "Building Go template %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

    return [TemplateInfo(
        types = ctx.attr.types,
        opt_types = ctx.attr.opt_types,
        consts = ctx.attr.consts,
        opt_consts = ctx.attr.opt_consts,
        deps = ctx.attr.deps,
        template = template,
    )]

go_template = rule(
    implementation = _go_template_impl,
    attrs = {
        "srcs": attr.label_list(doc = "the list of source files that comprise the template", mandatory = True, allow_files = True),
        "deps": attr.label_list(doc = "the standard dependency list", allow_files = True, cfg = "target"),
        "types": attr.string_list(doc = "the list of generic types in the template that are required to be specified"),
        "opt_types": attr.string_list(doc = "the list of generic types in the template that can but aren't required to be specified"),
        "consts": attr.string_list(doc = "the list of constants in the template that are required to be specified"),
        "opt_consts": attr.string_list(doc = "the list of constants in the template that can but aren't required to be specified"),
        "_tool": attr.label(executable = True, cfg = "host", default = Label("//tools/go_generics/go_merge")),
    },
)

def _go_template_instance_impl(ctx):
    info = ctx.attr.template[TemplateInfo]
    output = ctx.outputs.out

    # Check that all required types are defined.
    for t in info.types:
        if t not in ctx.attr.types:
            fail("Missing value for type %s in %s" % (t, ctx.attr.template.label))

    # Check that all defined types are expected by the template.
    for t in ctx.attr.types:
        if (t not in info.types) and (t not in info.opt_types):
            fail("Type %s is not a parameter to %s" % (t, ctx.attr.template.label))

    # Check that all required consts are defined.
    for t in info.consts:
        if t not in ctx.attr.consts:
            fail("Missing value for constant %s in %s" % (t, ctx.attr.template.label))

    # Check that all defined consts are expected by the template.
    for t in ctx.attr.consts:
        if (t not in info.consts) and (t not in info.opt_consts):
            fail("Const %s is not a parameter to %s" % (t, ctx.attr.template.label))

    # Build the argument list.
    args = ["-i=%s" % info.template.path, "-o=%s" % output.path]
    if ctx.attr.package:
        args.append("-p=%s" % ctx.attr.package)

    if len(ctx.attr.prefix) > 0:
        args.append("-prefix=%s" % ctx.attr.prefix)

    if len(ctx.attr.suffix) > 0:
        args.append("-suffix=%s" % ctx.attr.suffix)

    args += [("-t=%s=%s" % (p[0], p[1])) for p in ctx.attr.types.items()]
    args += [("-c=%s=%s" % (p[0], p[1])) for p in ctx.attr.consts.items()]
    args += [("-import=%s=%s" % (p[0], p[1])) for p in ctx.attr.imports.items()]

    if ctx.attr.anon:
        args.append("-anon")

    ctx.actions.run(
        inputs = [info.template],
        outputs = [output],
        mnemonic = "GoGenericsInstance",
        progress_message = "Building Go template instance %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

    return [DefaultInfo(
        files = depset([output]),
    )]

go_template_instance = rule(
    implementation = _go_template_instance_impl,
    attrs = {
        "template": attr.label(doc = "the label of the template to be instantiated", mandatory = True),
        "prefix": attr.string(doc = "a prefix to be added to globals in the template"),
        "suffix": attr.string(doc = "a suffix to be added to globals in the template"),
        "types": attr.string_dict(doc = "the map from generic type names to concrete ones"),
        "consts": attr.string_dict(doc = "the map from constant names to their values"),
        "imports": attr.string_dict(doc = "the map from imports used in types/consts to their import paths"),
        "anon": attr.bool(doc = "whether anoymous fields should be processed", mandatory = False, default = False),
        "package": attr.string(doc = "the package for the generated source file", mandatory = False),
        "out": attr.output(doc = "output file", mandatory = True),
        "_tool": attr.label(executable = True, cfg = "host", default = Label("//tools/go_generics")),
    },
)
