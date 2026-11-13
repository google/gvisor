"""Nogo rules."""

load("//tools:arch.bzl", "ARCHITECTURES", "arch_transition")
load("//tools/bazeldefs:go.bzl", "go_binary_archive", "go_context", "go_embed_libraries", "go_has_archive", "go_has_source", "go_importpath", "go_rule", "go_source_files", "nogo_extra_proto_deps")

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

# TODO(mpratt): It should be possible to migrate uses of these to
# extracting the target platform directly from the context.
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
    # Build the configuration for the stdlib.
    args = ctx.actions.args()
    go_ctx, inputs, raw_findings = _nogo_config(ctx, args, deps = [])

    # GOVERSION of std is set by the std go.mod.
    args.add("-GOVERSION-mod-file=%s" % go_ctx.stdlib_mod.path)

    # Build the analyzer command.
    facts_file = ctx.actions.declare_file(ctx.label.name + ".facts")
    findings_file = ctx.actions.declare_file(ctx.label.name + ".raw_findings")
    stdlib_srcs = go_ctx.stdlib_srcs if type(go_ctx.stdlib_srcs) == "list" else go_ctx.stdlib_srcs.to_list()
    args.add_all([
        "bundle",
        "-findings=%s" % findings_file.path,
        "-facts=%s" % facts_file.path,
        "-root=.*?/src/",
    ])
    args.add_all(stdlib_srcs)
    ctx.actions.run(
        # For the standard library, we need to include the full set of Go
        # sources in the inputs.
        inputs = inputs + stdlib_srcs,
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
        arguments = [args],
        toolchain = None,
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
            default = "//tools/nogo:nogo_tool",
            cfg = "exec",
        ),
        "_target": attr.label(
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
        "transitive_facts": "depset of (import path, facts file) pairs",
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

def _nogo_config(ctx, args, deps, attr = None):
    # Build a configuration for the given set of deps. This is most basic
    # configuration and is used by the stdlib. For a more complete config, the
    # _nogo_package_config function may be used.
    #
    # Returns (go_ctx, inputs, raw_findings).
    nogo_target_info = ctx.attr._target[NogoTargetInfo]
    go_ctx = go_context(ctx, goos = nogo_target_info.goos, goarch = nogo_target_info.goarch, attr = attr)
    args.add_all(go_ctx.nogo_args)
    args.add_all([
        "-go=%s" % go_ctx.go.path,
        "-GOOS=%s" % go_ctx.goos,
        "-GOARCH=%s" % go_ctx.goarch,
        "-tags=%s" % (",".join(go_ctx.gotags)),
    ])
    inputs = []
    raw_findings = []
    fact_sets = []
    for dep in deps:
        extras = nogo_extra_proto_deps(dep)
        for importpath, a_file, x_file in extras:
            args.add("-archive=%s=%s" % (importpath, a_file.path))
            args.add("-import=%s=%s" % (importpath, x_file.path))
            inputs.append(a_file)
            inputs.append(x_file)

        # There will be no file attribute set for all transitive dependencies
        # that are not go_library or go_binary rules, such as a proto rules.
        # This is handled by the ctx.rule.kind check above.
        info = dep[NogoInfo]
        if not hasattr(info, "facts"):
            continue

        # Configure where to find the export data and Go archive. Binary
        # dependencies also expose their archive rather than the executable.
        a_file, x_file = _select_objfile(info.binaries)
        args.add("-archive=%s=%s" % (info.importpath, a_file.path))
        args.add("-import=%s=%s" % (info.importpath, x_file.path))
        fact_sets.append(info.transitive_facts)

        # Collect all findings; duplicates are resolved at the end.
        raw_findings.extend(info.raw_findings)

        # Ensure the above are available as inputs.
        inputs.append(a_file)
        inputs.append(x_file)

    # Export data can expose types and methods from indirect imports. Their
    # facts must be available even without a direct source import.
    for importpath, facts_file in depset(transitive = fact_sets).to_list():
        args.add("-facts=%s=%s" % (importpath, facts_file.path))
        inputs.append(facts_file)

    return (go_ctx, inputs, raw_findings)

def _nogo_package_config(ctx, args, deps, importpath = None, objfiles = (None, None), attr = None):
    # See _nogo_config. This includes package details.
    #
    # Returns (go_ctx, inputs, raw_findings).
    go_ctx, inputs, raw_findings = _nogo_config(ctx, args, deps, attr = attr)

    # GOVERSION of packages are set by the project language version.
    args.add("-GOVERSION=%s" % go_ctx.lang_version)

    # Add the compiled package itself for analyzers that inspect object code.
    target_afile, target_xfile = objfiles
    if target_xfile != None:
        args.add("-archive=%s=%s" % (importpath, target_afile.path))
        args.add("-import=%s=%s" % (importpath, target_xfile.path))
        inputs.append(target_afile)
        inputs.append(target_xfile)

    # Add the standard library facts.
    stdlib_info = ctx.attr._nogo_stdlib[NogoStdlibInfo]
    stdlib_facts = stdlib_info.facts
    if stdlib_facts:
        inputs.append(stdlib_facts)
        args.add("-bundle=%s" % stdlib_facts.path)

    # Flatten all findings from all dependencies.
    #
    # This is done because all the filtering must be done at the
    # top-level nogo_test to dynamically apply a configuration.
    # This does not actually add any additional work here, but
    # will simply propagate the full list of files.
    raw_findings = stdlib_info.raw_findings + depset(raw_findings).to_list()
    return go_ctx, inputs, raw_findings

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
    is_binary = ctx.rule.kind in ("go_binary", "go_non_executable_binary")

    # A rule inheriting go_test has its own kind, but still compiles the
    # test sources. Older with_cfg frontends only export the compiled test.
    is_go_test = ctx.rule.kind.endswith("_test") and go_has_archive(target) and hasattr(ctx.rule.attr, "srcs")
    analyze_sources = is_binary or is_go_test or ctx.rule.kind in ("go_library", "go_tool_library")
    if analyze_sources:
        srcs = ctx.rule.files.srcs
        deps = ctx.rule.attr.deps
    elif ctx.rule.kind in ("go_proto_library", "go_wrap_cc"):
        # N.B. go_proto_library is strange because transitive dependencies are
        # not also go_proto_library targets. We don't care about analysis of
        # transitive dependencies, but we do need them for type checking. See
        # _nogo_config for the workaround that directly adds all proto
        # transitive dependencies.
        srcs = []
        deps = ctx.rule.attr.deps
    elif go_has_archive(target) and hasattr(ctx.rule.attr, "exports"):
        # Configuration wrappers forward one compiled target. Analyze that
        # target in its own configuration, then preserve its complete facts.
        exports = ctx.rule.attr.exports
        if type(exports) == "list":
            if len(exports) != 1:
                fail("nogo requires configuration wrappers to export one target")
            exports = exports[0]
        return [exports[NogoInfo]]
    else:
        return [NogoInfo()]

    # Match the compiler's source order: objectpath identifies named methods
    # by their source-order index, which compiler exports preserve.
    # https://github.com/golang/tools/blob/ea2f152dc/go/types/objectpath/objectpath.go#L718-L724
    has_source_info = analyze_sources and go_has_source(target)
    if has_source_info:
        srcs = go_source_files(target)

    # The canonical source view includes the sources of embedded targets.
    # Exclude those that the embed itself does not get analyzed.
    unanalyzed_srcs = {}
    for embed in go_embed_libraries(ctx.rule):
        info = embed[NogoInfo]
        if analyze_sources and go_has_source(embed):
            analyzed_srcs = {src: None for src in getattr(info, "srcs", [])}
            for src in go_source_files(embed):
                if src not in analyzed_srcs:
                    unanalyzed_srcs[src] = None
        if analyze_sources and not has_source_info:
            # Binary/test targets may expose only an archive. Retain their
            # own sources and rules_go's prepend order for each embed.
            if go_has_source(embed):
                srcs = go_source_files(embed) + srcs
            elif hasattr(info, "srcs"):
                srcs = info.srcs + srcs
        if hasattr(info, "deps"):
            deps = deps + info.deps
    if unanalyzed_srcs:
        srcs = [src for src in srcs if src not in unanalyzed_srcs]

    # Binary analysis needs the compiled Go archive, not the linked executable:
    # the linker can remove functions that checkescape still needs to inspect.
    if is_binary:
        archive = go_binary_archive(target)
        importpath = archive.importpath
        objfiles = (archive.file, archive.export_file)
        binaries = list(objfiles)
    else:
        importpath = "test" if is_go_test else go_importpath(target)
        binaries = target.files.to_list()
        compilation_outputs = binaries
        if hasattr(target.output_groups, "compilation_outputs"):
            compilation_outputs = compilation_outputs + target.output_groups.compilation_outputs.to_list()
        objfiles = _select_objfile(compilation_outputs)

    # Use the analyzed rule's transitioned Go configuration, including its build
    # tags, rather than the aspect's own attributes.
    args = ctx.actions.args()
    go_ctx, inputs, raw_findings = _nogo_package_config(ctx, args, deps, importpath = importpath, objfiles = objfiles, attr = ctx.rule.attr)

    # Build the argument file, and the runner.
    facts_file = ctx.actions.declare_file(ctx.label.name + ".facts")
    findings_file = ctx.actions.declare_file(ctx.label.name + ".findings")
    args.add_all([
        "check",
        "-findings=%s" % findings_file.path,
        "-facts=%s" % facts_file.path,
        "-package=%s" % importpath,
    ])
    args.add_all(srcs)
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
        arguments = [args],
        toolchain = None,
    )

    # Return the package facts as output.
    return [
        NogoInfo(
            facts = facts_file,
            transitive_facts = depset(
                [(importpath, facts_file)],
                transitive = [
                    dep[NogoInfo].transitive_facts
                    for dep in deps
                    if hasattr(dep[NogoInfo], "transitive_facts")
                ],
            ),
            raw_findings = raw_findings + [findings_file],
            importpath = importpath,
            binaries = binaries,
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
        "exports",
    ],
    attrs = {
        "_nogo": attr.label(
            default = "//tools/nogo:nogo_tool",
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

_TEST_FINDINGS = {arch: "nogo.%s.findings" % arch for arch in ARCHITECTURES}

def _nogo_test_impl(ctx):
    """Check nogo findings."""

    reports = {}

    # Collect all architecture-targets.
    for (arch, deps) in ctx.split_attr.deps.items():
        # Ensure there's a single dependency.
        if len(deps) != 1:
            fail("nogo_test requires exactly one dep.")
        raw_findings = deps[0][NogoInfo].raw_findings

        # Build a step that applies the configuration.
        config_srcs = ctx.attr.config[NogoConfigInfo].srcs
        findings = ctx.actions.declare_file(ctx.label.name + "." + arch + ".findings")
        args = ctx.actions.args()
        args.add("filter")
        args.add_all(config_srcs, format_each = "-config=%s")
        args.add("-output=%s" % findings.path)
        args.add_all(raw_findings)
        ctx.actions.run(
            inputs = raw_findings + ctx.files.srcs + config_srcs,
            outputs = [findings],
            tools = depset(ctx.files._nogo),
            executable = ctx.files._nogo[0],
            mnemonic = "GoStaticAnalysis",
            progress_message = "Generating %s" % ctx.label,
            arguments = [args],
            toolchain = None,
        )

        reports[_TEST_FINDINGS[arch]] = findings

    runner = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = runner, target_file = ctx.executable._nogo_target, is_executable = True)
    return [DefaultInfo(
        runfiles = ctx.runfiles(
            files = [ctx.executable._nogo_target],
            symlinks = reports,
        ).merge(ctx.attr._nogo_target[DefaultInfo].default_runfiles),
        executable = runner,
    ), OutputGroupInfo(
        # Tricorder consumes the per-architecture outputs of GoStaticAnalysis.
        nogo_findings = depset(reports.values()),
    )]

_nogo_test = rule(
    implementation = _nogo_test_impl,
    attrs = {
        "config": attr.label(
            mandatory = True,
            doc = "A rule of kind nogo_config.",
        ),
        "deps": attr.label_list(
            aspects = [nogo_aspect],
            doc = "Exactly one Go dependency to be analyzed.",
            cfg = arch_transition,
        ),
        "srcs": attr.label_list(
            allow_files = True,
            doc = "Relevant src files. This is ignored except to make the nogo_test directly affected by the files.",
        ),
        "_nogo": attr.label(
            default = "//tools/nogo:nogo_tool",
            cfg = "exec",
        ),
        "_nogo_target": attr.label(
            default = "//tools/nogo:nogo",
            cfg = "target",
            executable = True,
        ),
        "_target": attr.label(
            default = "//tools/nogo:target",
            cfg = arch_transition,
        ),
    },
    test = True,
)

def nogo_test_args(args = []):
    """Returns the analyzer arguments for checking the per-architecture reports."""
    return ["filter", "-test", "-text"] + args + _TEST_FINDINGS.values()

def nogo_test(name, args = [], **kwargs):
    """Checks the already-filtered reports for every architecture."""
    _nogo_test(
        name = name,
        args = nogo_test_args(args),
        **kwargs
    )

def _nogo_aspect_tricorder_impl(target, _ctx):
    if OutputGroupInfo not in target:
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

def _nogo_facts_render_impl(ctx):
    """Extract nogo facts."""

    # Rendering dependency facts needs neither an import path nor an archive
    # for the package containing the template.
    args = ctx.actions.args()
    go_ctx, inputs, _ = _nogo_package_config(ctx, args, ctx.attr.deps)

    # Build the runner.
    args.add_all([
        "render",
        "-template=%s" % ctx.files.template[0].path,
        "-output=%s" % ctx.outputs.output.path,
    ])
    args.add_all(ctx.files.srcs)
    ctx.actions.run(
        inputs = inputs + ctx.files.srcs + ctx.files.template,
        outputs = [ctx.outputs.output],
        tools = depset(go_ctx.runfiles.to_list() + ctx.files._nogo),
        executable = ctx.files._nogo[0],
        env = go_ctx.env,
        mnemonic = "GoStaticAnalysis",
        progress_message = "Generating %s" % ctx.label,
        arguments = [args],
    )

    # Return the output.
    return [DefaultInfo(files = depset([ctx.outputs.output]))]

nogo_facts_render = go_rule(
    rule,
    implementation = _nogo_facts_render_impl,
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
        "format": attr.bool(
            doc = "Whether to format output.",
            default = False,
        ),
        "_nogo": attr.label(
            default = "//tools/nogo:nogo_tool",
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
