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

# Normal Go builds use only the generated files for their target platform.
# The source archive is consumed by Go on both architectures.
def _go_source_transition_impl(settings, attr):
    arches = arch_transition_impl(settings, attr)
    if settings["//tools:export_go_sources"] or not attr.target_arch:
        return arches
    return {attr.target_arch: arches[attr.target_arch]}

_go_source_transition = transition(
    implementation = _go_source_transition_impl,
    inputs = ["//tools:export_go_sources"],
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

_arch_genrule = rule(
    implementation = _arch_genrule_impl,
    attrs = {
        "src": attr.label(
            doc = "Target producing one file per architecture.",
            cfg = _go_source_transition,
            mandatory = True,
        ),
        "target_arch": attr.string(),
        "template": attr.string(
            doc = "Template for the output files.",
            mandatory = True,
        ),
    },
    doc = "Copies a generated file under its architecture-specific name.",
    toolchains = _COPY_FILE_TOOLCHAINS,
)

def arch_genrule(name, src, template):
    """Copies src to template for each requested target architecture."""
    _arch_genrule(
        name = name,
        src = src,
        template = template,
        target_arch = _select_arch(amd64 = "amd64", arm64 = "arm64", default = ""),
    )
