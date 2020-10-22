"""Nogo rules."""

load("//tools/bazeldefs:go.bzl", "go_context", "go_importpath", "go_rule", "go_test_library")

NogoTargetInfo = provider(
    "information about the Go target",
    fields = {
        "goarch": "the build architecture (GOARCH)",
        "goos": "the build OS target (GOOS)",
    },
)

def _nogo_target_impl(ctx):
    return [NogoTargetInfo(
        goarch = ctx.attr.goarch,
        goos = ctx.attr.goos,
    )]

nogo_target = go_rule(
    rule,
    implementation = _nogo_target_impl,
    attrs = {
        # goarch is the build architecture. This will normally be provided by a
        # select statement, but this information is propagated to other rules.
        "goarch": attr.string(mandatory = True),
        # goos is similarly the build operating system target.
        "goos": attr.string(mandatory = True),
    },
)

def _nogo_objdump_tool_impl(ctx):
    # Construct the magic dump command.
    #
    # Note that in some cases, the input is being fed into the tool via stdin.
    # Unfortunately, the Go objdump tool expects to see a seekable file [1], so
    # we need the tool to handle this case by creating a temporary file.
    #
    # [1] https://github.com/golang/go/issues/41051
    nogo_target_info = ctx.attr._nogo_target[NogoTargetInfo]
    go_ctx = go_context(ctx, goos = nogo_target_info.goos, goarch = nogo_target_info.goarch)
    env_prefix = " ".join(["%s=%s" % (key, value) for (key, value) in go_ctx.env.items()])
    dumper = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.write(dumper, "\n".join([
        "#!/bin/bash",
        "set -euo pipefail",
        "if [[ $# -eq 0 ]]; then",
        " T=$(mktemp -u -t libXXXXXX.a)",
        " cat /dev/stdin > ${T}",
        "else",
        " T=$1;",
        "fi",
        "%s %s tool objdump ${T}" % (
            env_prefix,
            go_ctx.go.path,
        ),
        "if [[ $# -eq 0 ]]; then",
        " rm -rf ${T}",
        "fi",
        "",
    ]), is_executable = True)

    # Include the full runfiles.
    return [DefaultInfo(
        runfiles = ctx.runfiles(files = go_ctx.runfiles.to_list()),
        executable = dumper,
    )]

nogo_objdump_tool = go_rule(
    rule,
    implementation = _nogo_objdump_tool_impl,
    attrs = {
        "_nogo_target": attr.label(
            default = "//tools/nogo:target",
            cfg = "target",
        ),
    },
)

# NogoStdlibInfo is the set of standard library facts.
NogoStdlibInfo = provider(
    "information for nogo analysis (standard library facts)",
    fields = {
        "facts": "serialized standard library facts",
        "findings": "package findings (if relevant)",
    },
)

def _nogo_stdlib_impl(ctx):
    # Build the standard library facts.
    nogo_target_info = ctx.attr._nogo_target[NogoTargetInfo]
    go_ctx = go_context(ctx, goos = nogo_target_info.goos, goarch = nogo_target_info.goarch)
    facts = ctx.actions.declare_file(ctx.label.name + ".facts")
    findings = ctx.actions.declare_file(ctx.label.name + ".findings")
    config = struct(
        Srcs = [f.path for f in go_ctx.stdlib_srcs],
        GOOS = go_ctx.goos,
        GOARCH = go_ctx.goarch,
        Tags = go_ctx.tags,
    )
    config_file = ctx.actions.declare_file(ctx.label.name + ".cfg")
    ctx.actions.write(config_file, config.to_json())
    ctx.actions.run(
        inputs = [config_file] + go_ctx.stdlib_srcs,
        outputs = [facts, findings],
        tools = depset(go_ctx.runfiles.to_list() + ctx.files._nogo_objdump_tool),
        executable = ctx.files._nogo_check[0],
        mnemonic = "GoStandardLibraryAnalysis",
        progress_message = "Analyzing Go Standard Library",
        arguments = go_ctx.nogo_args + [
            "-objdump_tool=%s" % ctx.files._nogo_objdump_tool[0].path,
            "-stdlib=%s" % config_file.path,
            "-findings=%s" % findings.path,
            "-facts=%s" % facts.path,
        ],
    )

    # Return the stdlib facts as output.
    return [NogoStdlibInfo(
        facts = facts,
        findings = findings,
    )]

nogo_stdlib = go_rule(
    rule,
    implementation = _nogo_stdlib_impl,
    attrs = {
        "_nogo_check": attr.label(
            default = "//tools/nogo/check:check",
            cfg = "host",
        ),
        "_nogo_objdump_tool": attr.label(
            default = "//tools/nogo:objdump_tool",
            cfg = "host",
        ),
        "_nogo_target": attr.label(
            default = "//tools/nogo:target",
            cfg = "target",
        ),
    },
)

# NogoInfo is the serialized set of package facts for a nogo analysis.
#
# Each go_library rule will generate a corresponding nogo rule, which will run
# with the source files as input. Note however, that the individual nogo rules
# are simply stubs that enter into the shadow dependency tree (the "aspect").
NogoInfo = provider(
    "information for nogo analysis",
    fields = {
        "facts": "serialized package facts",
        "findings": "package findings (if relevant)",
        "importpath": "package import path",
        "binaries": "package binary files",
        "srcs": "original source files (for go_test support)",
        "deps": "original deps (for go_test support)",
    },
)

def _nogo_aspect_impl(target, ctx):
    # If this is a nogo rule itself (and not the shadow of a go_library or
    # go_binary rule created by such a rule), then we simply return nothing.
    # All work is done in the shadow properties for go rules. For a proto
    # library, we simply skip the analysis portion but still need to return a
    # valid NogoInfo to reference the generated binary.
    if ctx.rule.kind in ("go_library", "go_binary", "go_test", "go_tool_library"):
        srcs = ctx.rule.files.srcs
        deps = ctx.rule.attr.deps
    elif ctx.rule.kind in ("go_proto_library", "go_wrap_cc"):
        srcs = []
        deps = ctx.rule.attr.deps
    else:
        return [NogoInfo()]

    # If we're using the "library" attribute, then we need to aggregate the
    # original library sources and dependencies into this target to perform
    # proper type analysis.
    if ctx.rule.kind == "go_test":
        library = go_test_library(ctx.rule)
        if library != None:
            info = library[NogoInfo]
            if hasattr(info, "srcs"):
                srcs = srcs + info.srcs
            if hasattr(info, "deps"):
                deps = deps + info.deps

    # Start with all target files and srcs as input.
    inputs = target.files.to_list() + srcs

    # Generate a shell script that dumps the binary. Annoyingly, this seems
    # necessary as the context in which a run_shell command runs does not seem
    # to cleanly allow us redirect stdout to the actual output file. Perhaps
    # I'm missing something here, but the intermediate script does work.
    binaries = target.files.to_list()
    objfiles = [f for f in binaries if f.path.endswith(".a")]
    if len(objfiles) > 0:
        # Prefer the .a files for go_library targets.
        target_objfile = objfiles[0]
    else:
        # Use the raw binary for go_binary and go_test targets.
        target_objfile = binaries[0]
    inputs.append(target_objfile)

    # Extract the importpath for this package.
    if ctx.rule.kind == "go_test":
        # If this is a test, then it will not be imported by anything else.
        # We can safely set the importapth to just "test". Note that this
        # is necessary if the library also imports the core library (in
        # addition to including the sources directly), which happens in
        # some complex cases (seccomp_victim).
        importpath = "test"
    else:
        importpath = go_importpath(target)

    # Collect all info from shadow dependencies.
    fact_map = dict()
    import_map = dict()
    for dep in deps:
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
        import_map[info.importpath] = x_files[0]
        fact_map[info.importpath] = info.facts.path

        # Ensure the above are available as inputs.
        inputs.append(info.facts)
        inputs += info.binaries

    # Add the standard library facts.
    stdlib_info = ctx.attr._nogo_stdlib[NogoStdlibInfo]
    stdlib_facts = stdlib_info.facts
    inputs.append(stdlib_facts)

    # The nogo tool operates on a configuration serialized in JSON format.
    nogo_target_info = ctx.attr._nogo_target[NogoTargetInfo]
    go_ctx = go_context(ctx, goos = nogo_target_info.goos, goarch = nogo_target_info.goarch)
    facts = ctx.actions.declare_file(target.label.name + ".facts")
    findings = ctx.actions.declare_file(target.label.name + ".findings")
    escapes = ctx.actions.declare_file(target.label.name + ".escapes")
    config = struct(
        ImportPath = importpath,
        GoFiles = [src.path for src in srcs if src.path.endswith(".go")],
        NonGoFiles = [src.path for src in srcs if not src.path.endswith(".go")],
        GOOS = go_ctx.goos,
        GOARCH = go_ctx.goarch,
        Tags = go_ctx.tags,
        FactMap = fact_map,
        ImportMap = import_map,
        StdlibFacts = stdlib_facts.path,
    )
    config_file = ctx.actions.declare_file(target.label.name + ".cfg")
    ctx.actions.write(config_file, config.to_json())
    inputs.append(config_file)
    ctx.actions.run(
        inputs = inputs,
        outputs = [facts, findings, escapes],
        tools = depset(go_ctx.runfiles.to_list() + ctx.files._nogo_objdump_tool),
        executable = ctx.files._nogo_check[0],
        mnemonic = "GoStaticAnalysis",
        progress_message = "Analyzing %s" % target.label,
        arguments = go_ctx.nogo_args + [
            "-binary=%s" % target_objfile.path,
            "-objdump_tool=%s" % ctx.files._nogo_objdump_tool[0].path,
            "-package=%s" % config_file.path,
            "-findings=%s" % findings.path,
            "-facts=%s" % facts.path,
            "-escapes=%s" % escapes.path,
        ],
    )

    # Return the package facts as output.
    return [
        NogoInfo(
            facts = facts,
            findings = findings,
            importpath = importpath,
            binaries = binaries,
            srcs = srcs,
            deps = deps,
        ),
        OutputGroupInfo(
            # Expose all findings (should just be a single file). This can be
            # used for build analysis of the nogo findings.
            nogo_findings = depset([findings]),
            # Expose all escape analysis findings (see above).
            nogo_escapes = depset([escapes]),
        ),
    ]

nogo_aspect = go_rule(
    aspect,
    implementation = _nogo_aspect_impl,
    attr_aspects = [
        "deps",
        "library",
        "embed",
    ],
    attrs = {
        "_nogo_check": attr.label(
            default = "//tools/nogo/check:check",
            cfg = "host",
        ),
        "_nogo_stdlib": attr.label(
            default = "//tools/nogo:stdlib",
            cfg = "host",
        ),
        "_nogo_objdump_tool": attr.label(
            default = "//tools/nogo:objdump_tool",
            cfg = "host",
        ),
        "_nogo_target": attr.label(
            default = "//tools/nogo:target",
            cfg = "target",
        ),
    },
)

def _nogo_test_impl(ctx):
    """Check nogo findings."""

    # Build a runner that checks the facts files.
    findings = [dep[NogoInfo].findings for dep in ctx.attr.deps]
    runner = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run(
        inputs = findings + ctx.files.srcs,
        outputs = [runner],
        tools = depset(ctx.files._gentest),
        executable = ctx.files._gentest[0],
        mnemonic = "Gentest",
        progress_message = "Generating %s" % ctx.label,
        arguments = [runner.path] + [f.path for f in findings],
    )
    return [DefaultInfo(
        executable = runner,
    )]

_nogo_test = rule(
    implementation = _nogo_test_impl,
    attrs = {
        # deps should have only a single element.
        "deps": attr.label_list(aspects = [nogo_aspect]),
        # srcs exist here only to ensure that this target is
        # directly affected by changes to the source files.
        "srcs": attr.label_list(allow_files = True),
        "_gentest": attr.label(default = "//tools/nogo:gentest"),
    },
    test = True,
)

def nogo_test(name, srcs, library, **kwargs):
    tags = kwargs.pop("tags", []) + ["nogo"]
    _nogo_test(
        name = name,
        srcs = srcs,
        deps = [library],
        tags = tags,
        **kwargs
    )
