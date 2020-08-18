"""Generics support via go_generics."""

TemplateInfo = provider(
    fields = {
        "types": "required types",
        "opt_types": "optional types",
        "consts": "required consts",
        "opt_consts": "optional consts",
        "deps": "package dependencies",
        "file": "merged template",
    },
)

def _go_template_impl(ctx):
    srcs = ctx.files.srcs
    output = ctx.outputs.out

    args = ["-o=%s" % output.path] + [f.path for f in srcs]

    ctx.actions.run(
        inputs = srcs,
        outputs = [output],
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
        file = output,
    )]

"""
Generates a Go template from a set of Go files.

A Go template is similar to a go library, except that it has certain types that
can be replaced before usage. For example, one could define a templatized List
struct, whose elements are of type T, then instantiate that template for
T=segment, where "segment" is the concrete type.

Args:
  name: the name of the template.
  srcs: the list of source files that comprise the template.
  types: the list of generic types in the template that are required to be specified.
  opt_types: the list of generic types in the template that can but aren't required to be specified.
  consts: the list of constants in the template that are required to be specified.
  opt_consts: the list of constants in the template that can but aren't required to be specified.
  deps: the list of dependencies.
"""
go_template = rule(
    implementation = _go_template_impl,
    attrs = {
        "srcs": attr.label_list(mandatory = True, allow_files = True),
        "deps": attr.label_list(allow_files = True, cfg = "target"),
        "types": attr.string_list(),
        "opt_types": attr.string_list(),
        "consts": attr.string_list(),
        "opt_consts": attr.string_list(),
        "_tool": attr.label(executable = True, cfg = "host", default = Label("//tools/go_generics/go_merge")),
    },
    outputs = {
        "out": "%{name}_template.go",
    },
)

TemplateInstanceInfo = provider(
    fields = {
        "srcs": "source files",
    },
)

def _go_template_instance_impl(ctx):
    template = ctx.attr.template[TemplateInfo]
    output = ctx.outputs.out

    # Check that all required types are defined.
    for t in template.types:
        if t not in ctx.attr.types:
            fail("Missing value for type %s in %s" % (t, ctx.attr.template.label))

    # Check that all defined types are expected by the template.
    for t in ctx.attr.types:
        if (t not in template.types) and (t not in template.opt_types):
            fail("Type %s it not a parameter to %s" % (t, ctx.attr.template.label))

    # Check that all required consts are defined.
    for t in template.consts:
        if t not in ctx.attr.consts:
            fail("Missing value for constant %s in %s" % (t, ctx.attr.template.label))

    # Check that all defined consts are expected by the template.
    for t in ctx.attr.consts:
        if (t not in template.consts) and (t not in template.opt_consts):
            fail("Const %s it not a parameter to %s" % (t, ctx.attr.template.label))

    # Build the argument list.
    args = ["-i=%s" % template.file.path, "-o=%s" % output.path]
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
        inputs = [template.file],
        outputs = [output],
        mnemonic = "GoGenericsInstance",
        progress_message = "Building Go template instance %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

    return [TemplateInstanceInfo(
        srcs = [output],
    )]

"""
Instantiates a Go template by replacing all generic types with concrete ones.

Args:
  name: the name of the template instance.
  template: the label of the template to be instatiated.
  prefix: a prefix to be added to globals in the template.
  suffix: a suffix to be added to global in the template.
  types: the map from generic type names to concrete ones.
  consts: the map from constant names to their values.
  imports: the map from imports used in types/consts to their import paths.
  package: the name of the package the instantiated template will be compiled into.
"""
go_template_instance = rule(
    implementation = _go_template_instance_impl,
    attrs = {
        "template": attr.label(mandatory = True),
        "prefix": attr.string(),
        "suffix": attr.string(),
        "types": attr.string_dict(),
        "consts": attr.string_dict(),
        "imports": attr.string_dict(),
        "anon": attr.bool(mandatory = False, default = False),
        "package": attr.string(mandatory = False),
        "out": attr.output(mandatory = True),
        "_tool": attr.label(executable = True, cfg = "host", default = Label("//tools/go_generics")),
    },
)
