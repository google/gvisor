"""Nogo rules."""

load("//tools/bazeldefs:defs.bzl", "go_context", "go_importpath", "go_rule")

# NogoInfo is the serialized set of package facts for a nogo analysis.
#
# Each go_library rule will generate a corresponding nogo rule, which will run
# with the source files as input. Note however, that the individual nogo rules
# are simply stubs that enter into the shadow dependency tree (the "aspect").
NogoInfo = provider(
    fields = {
        "facts": "serialized package facts",
        "importpath": "package import path",
        "binaries": "package binary files",
    },
)

def _nogo_aspect_impl(target, ctx):
    # If this is a nogo rule itself (and not the shadow of a go_library or
    # go_binary rule created by such a rule), then we simply return nothing.
    # All work is done in the shadow properties for go rules. For a proto
    # library, we simply skip the analysis portion but still need to return a
    # valid NogoInfo to reference the generated binary.
    if ctx.rule.kind == "go_library":
        srcs = ctx.rule.files.srcs
    elif ctx.rule.kind == "go_proto_library" or ctx.rule.kind == "go_wrap_cc":
        srcs = []
    else:
        return [NogoInfo()]

    # Construct the Go environment from the go_context.env dictionary.
    env_prefix = " ".join(["%s=%s" % (key, value) for (key, value) in go_context(ctx).env.items()])

    # Start with all target files and srcs as input.
    inputs = target.files.to_list() + srcs

    # Generate a shell script that dumps the binary. Annoyingly, this seems
    # necessary as the context in which a run_shell command runs does not seem
    # to cleanly allow us redirect stdout to the actual output file. Perhaps
    # I'm missing something here, but the intermediate script does work.
    binaries = target.files.to_list()
    disasm_file = ctx.actions.declare_file(target.label.name + ".out")
    dumper = ctx.actions.declare_file("%s-dumper" % ctx.label.name)
    ctx.actions.write(dumper, "\n".join([
        "#!/bin/bash",
        "%s %s tool objdump %s > %s\n" % (
            env_prefix,
            go_context(ctx).go.path,
            [f.path for f in binaries if f.path.endswith(".a")][0],
            disasm_file.path,
        ),
    ]), is_executable = True)
    ctx.actions.run(
        inputs = binaries,
        outputs = [disasm_file],
        tools = go_context(ctx).runfiles,
        mnemonic = "GoObjdump",
        progress_message = "Objdump %s" % target.label,
        executable = dumper,
    )
    inputs.append(disasm_file)

    # Extract the importpath for this package.
    importpath = go_importpath(target)

    # The nogo tool requires a configfile serialized in JSON format to do its
    # work. This must line up with the nogo.Config fields.
    facts = ctx.actions.declare_file(target.label.name + ".facts")
    config = struct(
        ImportPath = importpath,
        GoFiles = [src.path for src in srcs if src.path.endswith(".go")],
        NonGoFiles = [src.path for src in srcs if not src.path.endswith(".go")],
        GOOS = go_context(ctx).goos,
        GOARCH = go_context(ctx).goarch,
        Tags = go_context(ctx).tags,
        FactMap = {},  # Constructed below.
        ImportMap = {},  # Constructed below.
        FactOutput = facts.path,
        Objdump = disasm_file.path,
    )

    # Collect all info from shadow dependencies.
    for dep in ctx.rule.attr.deps:
        # There will be no file attribute set for all transitive dependencies
        # that are not go_library or go_binary rules, such as a proto rules.
        # This is handled by the ctx.rule.kind check above.
        info = dep[NogoInfo]
        if not hasattr(info, "facts"):
            continue

        # Configure where to find the binary & fact files. Note that this will
        # use .x and .a regardless of whether this is a go_binary rule, since
        # these dependencies must be go_library rules.
        x_files = [f.path for f in info.binaries if f.path.endswith(".x")]
        if not len(x_files):
            x_files = [f.path for f in info.binaries if f.path.endswith(".a")]
        config.ImportMap[info.importpath] = x_files[0]
        config.FactMap[info.importpath] = info.facts.path

        # Ensure the above are available as inputs.
        inputs.append(info.facts)
        inputs += info.binaries

    # Write the configuration and run the tool.
    config_file = ctx.actions.declare_file(target.label.name + ".cfg")
    ctx.actions.write(config_file, config.to_json())
    inputs.append(config_file)

    # Run the nogo tool itself.
    ctx.actions.run(
        inputs = inputs,
        outputs = [facts],
        tools = go_context(ctx).runfiles,
        executable = ctx.files._nogo[0],
        mnemonic = "GoStaticAnalysis",
        progress_message = "Analyzing %s" % target.label,
        arguments = ["-config=%s" % config_file.path],
    )

    # Return the package facts as output.
    return [NogoInfo(
        facts = facts,
        importpath = importpath,
        binaries = binaries,
    )]

nogo_aspect = go_rule(
    aspect,
    implementation = _nogo_aspect_impl,
    attr_aspects = ["deps"],
    attrs = {
        "_nogo": attr.label(
            default = "//tools/nogo/check:check",
            allow_single_file = True,
        ),
    },
)

def _nogo_test_impl(ctx):
    """Check nogo findings."""

    # Build a runner that checks for the existence of the facts file. Note that
    # the actual build will fail in the case of a broken analysis. We things
    # this way so that any test applied is effectively pushed down to all
    # upstream dependencies through the aspect.
    inputs = []
    runner = ctx.actions.declare_file("%s-executer" % ctx.label.name)
    runner_content = ["#!/bin/bash"]
    for dep in ctx.attr.deps:
        info = dep[NogoInfo]
        inputs.append(info.facts)

        # Draw a sweet unicode checkmark with the package name (in green).
        runner_content.append("echo -e \"\\033[0;32m\\xE2\\x9C\\x94\\033[0;31m\\033[0m %s\"" % info.importpath)
    runner_content.append("exit 0\n")
    ctx.actions.write(runner, "\n".join(runner_content), is_executable = True)
    return [DefaultInfo(
        runfiles = ctx.runfiles(files = inputs),
        executable = runner,
    )]

_nogo_test = rule(
    implementation = _nogo_test_impl,
    attrs = {
        "deps": attr.label_list(aspects = [nogo_aspect]),
    },
    test = True,
)

def nogo_test(**kwargs):
    tags = kwargs.pop("tags", []) + ["nogo"]
    _nogo_test(tags = tags, **kwargs)
