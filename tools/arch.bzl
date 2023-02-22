"""Wrappers for architecture-specific rules."""

load("//tools/bazeldefs:defs.bzl", _amd64_config = "amd64_config", _arch_config = "arch_config", _arm64_config = "arm64_config", _select_arch = "select_arch", _transition_allowlist = "transition_allowlist")

# Export arch rules.
select_arch = _select_arch
transition_allowlist = _transition_allowlist

def _arch_transition_impl(settings, attr):
    return {
        "arm64": _arm64_config(settings, attr),
        "amd64": _amd64_config(settings, attr),
    }

arch_transition = transition(
    implementation = _arch_transition_impl,
    inputs = [],
    outputs = _arch_config,
)

def _arch_genrule_impl(ctx):
    """Runs a command with inputs from multiple architectures.

    The command will be run multiple times, with the provided
    template rendered using the architecture for the output.
    """
    outputs = []
    for (arch, src) in ctx.split_attr.src.items():
        # Calculate the template for this output file.
        output = ctx.actions.declare_file(ctx.attr.template % arch)
        outputs.append(output)

        # Copy the specific generated source.
        input_files = src[DefaultInfo].files
        ctx.actions.run_shell(
            inputs = input_files,
            outputs = [output],
            command = "cp %s %s" % (
                " ".join([f.path for f in input_files.to_list()]),
                output.path,
            ),
        )
    return [DefaultInfo(
        files = depset(outputs),
    )]

arch_genrule = rule(
    implementation = _arch_genrule_impl,
    attrs = {
        "src": attr.label(
            doc = "Sources for the genrule.",
            cfg = arch_transition,
        ),
        "template": attr.string(
            doc = "Template for the output files.",
            mandatory = True,
        ),
        "_allowlist_function_transition": attr.label(
            default = _transition_allowlist,
        ),
    },
)
