"""Nogo rules."""

load("//tools/bazeldefs:defs.bzl", "BuildSettingInfo")
load("//tools/bazeldefs:go.bzl", "go_context", "go_embed_libraries", "go_importpath", "go_rule")

NogoConfigInfo = provider(
    "information about a nogo configuration",
    fields = {
        "srcs": "the collection of configuration files",
    },
)

def _nogo_config_impl(ctx):
    return [NogoConfigInfo(
        srcs = ctx.files.srcs,
    )]

nogo_config = rule(
    implementation = _nogo_config_impl,
    attrs = {
        "srcs": attr.label_list(
            doc = "a list of yaml files (schema defined by tool/nogo/config.go).",
            allow_files = True,
        ),
    },
)

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
        "goarch": attr.string(
            doc = "the Go build architecture (propagated to other rules).",
            mandatory = True,
        ),
        "goos": attr.string(
            doc = "the Go OS target (propagated to other rules).",
            mandatory = True,
        ),
    },
)

# NogoStdlibInfo is the set of standard library facts.
NogoStdlibInfo = provider(
    "information for nogo analysis (standard library facts)",
    fields = {
        "facts": "serialized standard library facts",
        "raw_findings": "raw package findings (if relevant)",
    },
)

def _nogo_stdlib_impl(ctx):
    # If this is disabled, return nothing.
    if not ctx.attr._nogo_full[BuildSettingInfo].value:
        return [NogoStdlibInfo(
            facts = None,
            raw_findings = [],
        )]

    # Build the configuration for the stdlib.
    go_ctx, args, inputs, raw_findings = _nogo_config(ctx, deps = [])

    # Build the analyzer command.
    facts_file = ctx.actions.declare_file(ctx.label.name + ".facts")
    findings_file = ctx.actions.declare_file(ctx.label.name + ".raw_findings")
    ctx.actions.run(
        # For the standard library, we need to include the full set of Go
        # sources in the inputs.
        inputs = inputs + go_ctx.stdlib_srcs,
        outputs = [facts_file, findings_file],
        tools = depset(go_ctx.runfiles.to_list() + ctx.files._nogo),
        executable = ctx.files._nogo[0],
        env = go_ctx.env,
        mnemonic = "GoStandardLibraryAnalysis",
        progress_message = "Analyzing Go Standard Library",
        # Since these actions are generally I/O bound, reading source files,
        # facts, binaries and serializing results, disable sandboxing. This can
        # be enabled without any issues for correctness, but we want to avoid
        # paying the FUSE penalty.
        execution_requirements = {"no-sandbox": "1"},
        arguments = args + [
            "bundle",
            "-findings=%s" % findings_file.path,
            "-facts=%s" % facts_file.path,
            "-root=.*?/src/",
        ] + [f.path for f in go_ctx.stdlib_srcs],
    )

    # Return the stdlib facts as output.
    return [NogoStdlibInfo(
        facts = facts_file,
        raw_findings = raw_findings + [findings_file],
    ), DefaultInfo(
        # Declare the facts and findings as default outputs. This is not
        # strictly required, but ensures that the target still perform analysis
        # when built directly rather than just indirectly via a nogo_test.
        files = depset([facts_file, findings_file]),
    )]

nogo_stdlib = go_rule(
    rule,
    implementation = _nogo_stdlib_impl,
    attrs = {
        "_nogo": attr.label(
            default = "//tools/nogo:nogo",
            cfg = "exec",
        ),
        "_target": attr.label(
            default = "//tools/nogo:target",
            cfg = "target",
        ),
        "_nogo_full": attr.label(
            default = "//tools/nogo:full",
            cfg = "exec",
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
        "raw_findings": "raw package findings (if relevant)",
        "importpath": "package import path",
        "binaries": "package binary files",
        "srcs": "srcs (for go_test support)",
        "deps": "deps (for go_test support)",
    },
)

def _select_objfile(files):
    """Returns (.a file, .x file).

    If no .x file is available, then the first .x file will be returned
    instead, and vice versa. If neither are available, then the first provided
    file will be returned."""
    a_files = [f for f in files if f.path.endswith(".a")]
    x_files = [f for f in files if f.path.endswith(".x")]
    if not len(x_files) and not len(a_files):
        if not len(files):
            return (None, None)
        return (files[0], files[0])
    if not len(x_files):
        x_files = a_files
    if not len(a_files):
        a_files = x_files
    return a_files[0], x_files[0]

def _nogo_config(ctx, deps):
    # Build a configuration for the given set of deps. This is most basic
    # configuration and is used by the stdlib. For a more complete config, the
    # _nogo_package_config function may be used.
    #
    # Returns (go_ctx, args, inputs, raw_findings).
    nogo_target_info = ctx.attr._target[NogoTargetInfo]
    go_ctx = go_context(ctx, goos = nogo_target_info.goos, goarch = nogo_target_info.goarch)
    args = go_ctx.nogo_args + [
        "-go=%s" % go_ctx.go.path,
        "-GOOS=%s" % go_ctx.goos,
        "-GOARCH=%s" % go_ctx.goarch,
        "-tags=%s" % (",".join(go_ctx.gotags)),
    ]
    inputs = []
    raw_findings = []
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
        a_file, x_file = _select_objfile(info.binaries)
        args.append("-archive=%s=%s" % (info.importpath, a_file.path))
        args.append("-import=%s=%s" % (info.importpath, x_file.path))
        args.append("-facts=%s=%s" % (info.importpath, info.facts.path))

        # Collect all findings; duplicates are resolved at the end.
        raw_findings.extend(info.raw_findings)

        # Ensure the above are available as inputs.
        inputs.append(a_file)
        inputs.append(x_file)
        inputs.append(info.facts)

    return (go_ctx, args, inputs, raw_findings)

def _nogo_package_config(ctx, deps, importpath = None, target = None):
    # See _nogo_config. This includes package details.
    #
    # Returns (go_ctx, args, inputs, raw_findings).
    go_ctx, args, inputs, raw_findings = _nogo_config(ctx, deps)

    # Add the module itself, for the type sanity check. This applies only to
    # the libraries, and not binaries or tests.
    binaries = []
    if target != None:
        binaries.extend(target.files.to_list())
    target_afile, target_xfile = _select_objfile(binaries)
    if target_xfile != None:
        args.append("-archive=%s=%s" % (importpath, target_afile.path))
        args.append("-import=%s=%s" % (importpath, target_xfile.path))
        inputs.append(target_afile)
        inputs.append(target_xfile)

    # Add the standard library facts.
    stdlib_info = ctx.attr._nogo_stdlib[NogoStdlibInfo]
    stdlib_facts = stdlib_info.facts
    if stdlib_facts:
        inputs.append(stdlib_facts)
        args.append("-bundle=%s" % stdlib_facts.path)

    # Flatten all findings from all dependencies.
    #
    # This is done because all the filtering must be done at the
    # top-level nogo_test to dynamically apply a configuration.
    # This does not actually add any additional work here, but
    # will simply propagate the full list of files.
    raw_findings = stdlib_info.raw_findings + depset(raw_findings).to_list()
    return go_ctx, args, inputs, raw_findings

def _nogo_aspect_impl(target, ctx):
    # If this is a nogo rule itself (and not the shadow of a go_library or
    # go_binary rule created by such a rule), then we simply return nothing.
    # All work is done in the shadow properties for go rules. For a proto
    # library, we simply skip the analysis portion but still need to return a
    # valid NogoInfo to reference the generated binary.
    #
    # Note that we almost exclusively use go_library, not go_tool_library.
    # This is because nogo is manually annotated, so the go_tool_library kind
    # is not needed to avoid dependency loops. Unfortunately, bazel coverdata
    # is exported *only* as a go_tool_library. This does not cause a problem,
    # since there is guaranteed to be no conflict. However for consistency,
    # we should not introduce new go_tool_library dependencies unless strictly
    # necessary.
    if ctx.rule.kind in ("go_library", "go_tool_library", "go_binary", "go_test"):
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
    for embed in go_embed_libraries(ctx.rule):
        info = embed[NogoInfo]
        if hasattr(info, "srcs"):
            srcs = srcs + info.srcs
        if hasattr(info, "deps"):
            deps = deps + info.deps

    # Extract the importpath for this package.
    if ctx.rule.kind == "go_test":
        importpath = "test"
    else:
        importpath = go_importpath(target)

    # Build a complete configuration, referring to the library rule.
    go_ctx, args, inputs, raw_findings = _nogo_package_config(ctx, deps, importpath = importpath, target = target)

    # Build the argument file, and the runner.
    facts_file = ctx.actions.declare_file(ctx.label.name + ".facts")
    findings_file = ctx.actions.declare_file(ctx.label.name + ".findings")
    ctx.actions.run(
        inputs = inputs + srcs,
        outputs = [findings_file, facts_file],
        tools = depset(go_ctx.runfiles.to_list() + ctx.files._nogo),
        executable = ctx.files._nogo[0],
        env = go_ctx.env,
        mnemonic = "GoStaticAnalysis",
        progress_message = "Analyzing %s" % target.label,
        # See above.
        execution_requirements = {"no-sandbox": "1"},
        arguments = args + [
            "check",
            "-findings=%s" % findings_file.path,
            "-facts=%s" % facts_file.path,
            "-package=%s" % importpath,
        ] + [src.path for src in srcs],
    )

    # Return the package facts as output.
    return [
        NogoInfo(
            facts = facts_file,
            raw_findings = raw_findings + [findings_file],
            importpath = importpath,
            binaries = target.files.to_list(),
            srcs = srcs,
            deps = deps,
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
        "_nogo": attr.label(
            default = "//tools/nogo:nogo",
            cfg = "exec",
        ),
        "_target": attr.label(
            default = "//tools/nogo:target",
            cfg = "target",
        ),
        # The name of this attribute must not be _stdlib, since that
        # appears to be reserved for some internal bazel use.
        "_nogo_stdlib": attr.label(
            default = "//tools/nogo:stdlib",
            cfg = "target",
        ),
    },
)

def _nogo_test_impl(ctx):
    """Check nogo findings."""
    nogo_target_info = ctx.attr._target[NogoTargetInfo]

    # Ensure there's a single dependency.
    if len(ctx.attr.deps) != 1:
        fail("nogo_test requires exactly one dep.")
    raw_findings = ctx.attr.deps[0][NogoInfo].raw_findings

    # Build a step that applies the configuration.
    config_srcs = ctx.attr.config[NogoConfigInfo].srcs
    findings = ctx.actions.declare_file(ctx.label.name + ".findings")
    ctx.actions.run(
        inputs = raw_findings + ctx.files.srcs + config_srcs,
        outputs = [findings],
        tools = depset(ctx.files._nogo),
        executable = ctx.files._nogo[0],
        mnemonic = "GoStaticAnalysis",
        progress_message = "Generating %s" % ctx.label,
        # See above.
        execution_requirements = {"no-sandbox": "1"},
        arguments = ["filter"] +
                    ["-config=%s" % f.path for f in config_srcs] +
                    ["-output=%s" % findings.path] +
                    [f.path for f in raw_findings],
    )

    # Build a runner that checks the filtered facts.
    #
    # Note that this calls the filter binary without any configuration, so all
    # findings will be included. But this is expected, since we've already
    # filtered out everything that should not be included.
    runner = ctx.actions.declare_file(ctx.label.name)
    runner_content = [
        "#!/bin/bash",
        "exec %s filter -test -text %s" % (ctx.files._nogo[0].short_path, findings.short_path),
        "",
    ]
    ctx.actions.write(runner, "\n".join(runner_content), is_executable = True)

    return [DefaultInfo(
        # The runner just executes the filter again, on the
        # newly generated filtered findings. We still need
        # the filter tool as part of our runfiles, however.
        runfiles = ctx.runfiles(files = ctx.files._nogo + [findings]),
        executable = runner,
    ), OutputGroupInfo(
        # Propagate the filtered filters, for consumption by
        # build tooling. Note that the build tooling typically
        # pays attention to the mnemoic above, so this must be
        # what is expected by the tooling.
        nogo_findings = depset([findings]),
    )]

nogo_test = rule(
    implementation = _nogo_test_impl,
    attrs = {
        "config": attr.label(
            mandatory = True,
            doc = "A rule of kind nogo_config.",
        ),
        "deps": attr.label_list(
            aspects = [nogo_aspect],
            doc = "Exactly one Go dependency to be analyzed.",
        ),
        "srcs": attr.label_list(
            allow_files = True,
            doc = "Relevant src files. This is ignored except to make the nogo_test directly affected by the files.",
        ),
        "_nogo": attr.label(
            default = "//tools/nogo:nogo",
            cfg = "exec",
        ),
        "_target": attr.label(
            default = "//tools/nogo:target",
            cfg = "target",
        ),
        "_nogo_full": attr.label(
            default = "//tools/nogo:full",
            cfg = "exec",
        ),
    },
    test = True,
)

def _nogo_aspect_tricorder_impl(target, ctx):
    if ctx.rule.kind != "nogo_test" or OutputGroupInfo not in target:
        return []
    if not hasattr(target[OutputGroupInfo], "nogo_findings"):
        return []
    return [
        OutputGroupInfo(tricorder = target[OutputGroupInfo].nogo_findings),
    ]

# Trivial aspect that forwards the findings from a nogo_test rule to
# go/tricorder, which reads from the `tricorder` output group.
nogo_aspect_tricorder = aspect(
    implementation = _nogo_aspect_tricorder_impl,
)

def _nogo_facts_impl(ctx):
    """Extract nogo facts."""

    # Build a complete configuration. Note that we don't care about the import
    # path, since this will generate facts only. We use ctx as the target here,
    # since this will refer to ctx.files (which contains no binaries).
    go_ctx, args, inputs, _ = _nogo_package_config(ctx, ctx.attr.deps)

    # Build the runner.
    ctx.actions.run(
        inputs = inputs + ctx.files.srcs + ctx.files.template,
        outputs = [ctx.outputs.output],
        tools = depset(go_ctx.runfiles.to_list() + ctx.files._nogo),
        executable = ctx.files._nogo[0],
        env = go_ctx.env,
        mnemonic = "GoStaticAnalysis",
        progress_message = "Generating %s" % ctx.label,
        # See above.
        execution_requirements = {"no-sandbox": "1"},
        arguments = args + [
            "render",
            "-template=%s" % ctx.files.template[0].path,
            "-output=%s" % ctx.outputs.output.path,
        ] + [src.path for src in ctx.files.srcs],
    )

    # Return the output.
    return [DefaultInfo(files = depset([ctx.outputs.output]))]

nogo_facts = go_rule(
    rule,
    implementation = _nogo_facts_impl,
    attrs = {
        "srcs": attr.label_list(
            allow_files = True,
            doc = "Source files to be processed.",
            mandatory = True,
        ),
        "deps": attr.label_list(
            aspects = [nogo_aspect],
            doc = "Go dependencies to be analyzed.",
        ),
        "template": attr.label(
            allow_files = True,
            doc = "Template to be rendered for the output.",
            mandatory = True,
        ),
        "output": attr.output(
            doc = "Output file to be rendered.",
            mandatory = True,
        ),
        "_nogo": attr.label(
            default = "//tools/nogo:nogo",
            cfg = "exec",
        ),
        # See _nogo_aspect, above.
        "_nogo_stdlib": attr.label(
            default = "//tools/nogo:stdlib",
            cfg = "target",
        ),
        "_target": attr.label(
            default = "//tools/nogo:target",
            cfg = "target",
        ),
    },
)
