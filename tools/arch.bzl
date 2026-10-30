"""Wrappers for architecture-specific rules."""

load("//tools/bazeldefs:defs.bzl", _COPY_FILE_TOOLCHAINS = "COPY_FILE_TOOLCHAINS", _amd64_config = "amd64_config", _arch_config = "arch_config", _arm64_config = "arm64_config", _copy_file_action = "copy_file_action", _select_arch = "select_arch", _transition_allowlist = "transition_allowlist")

# Export arch rules.
select_arch = _select_arch
transition_allowlist = _transition_allowlist

def arch_transition_impl(settings, attr):
    return {
        "arm64": _arm64_config(settings, attr),
        "amd64": _amd64_config(settings, attr),
    }

arch_transition = transition(
    implementation = arch_transition_impl,
    inputs = [],
    outputs = _arch_config,
)

def _arch_genrule_impl(ctx):
    outputs = []
    for arch, src in ctx.split_attr.src.items():
        (src_file,) = src[DefaultInfo].files.to_list()
        output = ctx.actions.declare_file(ctx.attr.template % arch)
        _copy_file_action(ctx, src_file, output)
        outputs.append(output)
    return [DefaultInfo(files = depset(outputs))]

arch_genrule = rule(
    implementation = _arch_genrule_impl,
    attrs = {
        "src": attr.label(
            doc = "Target producing one file per architecture.",
            cfg = arch_transition,
            mandatory = True,
        ),
        "template": attr.string(
            doc = "Template for the output files.",
            mandatory = True,
        ),
    },
    doc = "Copies an output built for each architecture to its formatted name.",
    toolchains = _COPY_FILE_TOOLCHAINS,
)
