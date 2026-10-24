"""Nogo rules."""

load("//tools:arch.bzl", "arch_transition")
load("//tools/bazeldefs:go.bzl", "go_context", "go_embed_libraries", "go_has_source", "go_package", "go_rule", "go_source_files")

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
        "exports": "directory of standard library export data",
        "raw_findings": "raw package findings (if relevant)",
    },
)

def _nogo_stdlib_impl(ctx):
    # Build the configuration for the stdlib.
    go_ctx, args, inputs, raw_findings = _nogo_config(ctx, deps = [])

    # GOVERSION of std is set by the std go.mod.
    args.append("-GOVERSION-mod-file=%s" % go_ctx.stdlib_mod.path)

    # Build the analyzer command.
    facts_file = ctx.actions.declare_file(ctx.label.name + ".facts")
    exports = ctx.actions.declare_directory(ctx.label.name + ".exports")
    findings_file = ctx.actions.declare_file(ctx.label.name + ".raw_findings")
    stdlib_srcs = go_ctx.stdlib_srcs if type(go_ctx.stdlib_srcs) == "list" else go_ctx.stdlib_srcs.to_list()
    ctx.actions.run(
        # For the standard library, we need to include the full set of Go
        # sources in the inputs.
        inputs = inputs + stdlib_srcs,
        outputs = [facts_file, findings_file, exports],
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
            "-export=%s" % exports.path,
            "-findings=%s" % findings_file.path,
            "-facts=%s" % facts_file.path,
            "-root=.*?/src/",
        ] + [f.path for f in stdlib_srcs],
        toolchain = None,
    )

    # Return the stdlib facts as output.
    return [NogoStdlibInfo(
        facts = facts_file,
        exports = exports,
        raw_findings = raw_findings + [findings_file],
    ), DefaultInfo(
        # Declare the facts and findings as default outputs. This is not
        # strictly required, but ensures that the target still perform analysis
        # when built directly rather than just indirectly via a nogo_test.
        files = depset([facts_file, findings_file, exports]),
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
        "export": "source-derived package export data",
        "transitive_facts": "depset of (import path, facts file) pairs",
        "raw_findings": "raw package findings (if relevant)",
        "importpath": "canonical package path",
        "importpaths": "source import paths for the package",
        "archive": "compiled package archive for binary analyzers",
        "srcs": "srcs (for go_test support)",
        "deps": "deps (for go_test support)",
    },
)

def _nogo_config(ctx, deps, attr = None):
    # Build a configuration for the given set of deps. This is most basic
    # configuration and is used by the stdlib. For a more complete config, the
    # _nogo_package_config function may be used.
    #
    # Returns (go_ctx, args, inputs, raw_findings).
    nogo_target_info = ctx.attr._target[NogoTargetInfo]
    go_ctx = go_context(ctx, goos = nogo_target_info.goos, goarch = nogo_target_info.goarch, attr = attr)
    args = go_ctx.nogo_args + [
        "-go=%s" % go_ctx.go.path,
        "-GOOS=%s" % go_ctx.goos,
        "-GOARCH=%s" % go_ctx.goarch,
        "-tags=%s" % (",".join(go_ctx.gotags)),
    ]
    inputs = []
    raw_findings = []
    fact_sets = []
    for dep in deps:
        # Non-Go dependencies do not produce export data or facts.
        info = dep[NogoInfo]
        if not hasattr(info, "facts"):
            continue

        args.append("-archive=%s=%s" % (info.importpath, info.archive.path))
        args.append("-import=%s=%s" % (info.importpath, info.export.path))
        for importpath in info.importpaths:
            if importpath != info.importpath:
                args.append("-import-map=%s=%s" % (importpath, info.importpath))
        fact_sets.append(info.transitive_facts)
        raw_findings.extend(info.raw_findings)
        inputs.extend([info.archive, info.export])

    # Export data can expose types and methods from indirect imports. Their
    # facts must be available even without a direct source import.
    for importpath, facts_file in depset(transitive = fact_sets).to_list():
        args.append("-facts=%s=%s" % (importpath, facts_file.path))
        inputs.append(facts_file)

    return (go_ctx, args, inputs, raw_findings)

def _nogo_package_config(ctx, deps, importpath = None, archive = None, attr = None):
    # See _nogo_config. This includes package details.
    #
    # Returns (go_ctx, args, inputs, raw_findings).
    go_ctx, args, inputs, raw_findings = _nogo_config(ctx, deps, attr = attr)

    # GOVERSION of packages are set by the project language version.
    args.append("-GOVERSION=%s" % go_ctx.lang_version)

    # Add the compiled package itself for analyzers that inspect object code.
    if archive != None:
        args.append("-archive=%s=%s" % (importpath, archive.path))
        inputs.append(archive)

    # Add the standard library facts.
    stdlib_info = ctx.attr._nogo_stdlib[NogoStdlibInfo]
    inputs.append(stdlib_info.exports)
    args.append("-stdlib=%s" % stdlib_info.exports.path)
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
    # Proto compilers inject Go runtime dependencies into generated packages.
    # Traverse those targets instead of importing the compiler's export files.
    if ctx.rule.kind == "_go_proto_compiler":
        return [NogoInfo(deps = ctx.rule.attr.deps)]

    is_binary = ctx.rule.kind in ("go_binary", "go_non_executable_binary")
    is_test = ctx.rule.kind == "go_test"
    analyze_sources = is_binary or ctx.rule.kind in ("go_library", "go_tool_library", "go_test", "go_proto_library", "go_wrap_cc")
    if not analyze_sources and not go_has_source(target):
        return [NogoInfo()]

    deps = list(ctx.rule.attr.deps) if hasattr(ctx.rule.attr, "deps") else []
    for embed in go_embed_libraries(ctx.rule):
        info = embed[NogoInfo]
        if hasattr(info, "deps"):
            deps.extend(info.deps)
    if not analyze_sources:
        # Source-only GoInfo providers contribute their dependencies when
        # embedded; the consuming package owns compilation and analysis.
        return [NogoInfo(deps = deps)]

    if ctx.rule.kind == "go_proto_library":
        compilers = [ctx.rule.attr.compiler] if ctx.rule.attr.compiler else ctx.rule.attr.compilers
        for compiler in compilers:
            deps.extend(compiler[NogoInfo].deps)

    if is_test:
        # rules_go does not expose GoInfo for test binaries. Preserve the
        # source package under test rather than analyzing its generated main.
        srcs = list(ctx.rule.files.srcs)
        for embed in go_embed_libraries(ctx.rule):
            # Match rules_go's prepend order, including source-only embeds.
            if go_has_source(embed):
                srcs = go_source_files(embed) + srcs
            elif hasattr(embed[NogoInfo], "srcs"):
                srcs = embed[NogoInfo].srcs + srcs
        importpath = "test"
        importpaths = []

        # The GoArchive provider describes generated testmain, while this
        # output group contains the source package's internal/external code.
        archive, _ = target.output_groups.compilation_outputs.to_list()
    else:
        package = go_package(target)
        srcs = package.srcs
        importpath = package.importpath
        importpaths = package.importpaths
        archive = package.archive

    # Use the analyzed rule's transitioned Go configuration, including its build
    # tags, rather than the aspect's own attributes.
    go_ctx, args, inputs, raw_findings = _nogo_package_config(ctx, deps, importpath = importpath, archive = archive, attr = ctx.rule.attr)

    # Build the argument file, and the runner.
    facts_file = ctx.actions.declare_file(ctx.label.name + ".facts")
    export_file = ctx.actions.declare_file(ctx.label.name + ".export")
    findings_file = ctx.actions.declare_file(ctx.label.name + ".findings")
    ctx.actions.run(
        inputs = inputs + srcs,
        outputs = [findings_file, facts_file, export_file],
        tools = depset(go_ctx.runfiles.to_list() + ctx.files._nogo),
        executable = ctx.files._nogo[0],
        env = go_ctx.env,
        mnemonic = "GoStaticAnalysis",
        progress_message = "Analyzing %s" % target.label,
        # See above.
        execution_requirements = {"no-sandbox": "1"},
        arguments = args + [
            "check",
            "-export=%s" % export_file.path,
            "-findings=%s" % findings_file.path,
            "-facts=%s" % facts_file.path,
            "-package=%s" % importpath,
        ] + [src.path for src in srcs],
        toolchain = None,
    )

    # Return the package facts as output.
    return [
        NogoInfo(
            facts = facts_file,
            export = export_file,
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
            importpaths = importpaths,
            archive = archive,
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
        "compiler",
        "compilers",
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

def _nogo_test_impl(ctx):
    """Check nogo findings."""

    # Build a runner that checks the filtered facts.
    runner = ctx.actions.declare_file(ctx.label.name)
    runner_content = ["#!/bin/bash"]
    runner_footer = list()
    all_findings = list()

    # Collect all architecture-targets.
    for (arch, deps) in ctx.split_attr.deps.items():
        # Ensure there's a single dependency.
        if len(deps) != 1:
            fail("nogo_test requires exactly one dep.")
        raw_findings = deps[0][NogoInfo].raw_findings

        # Build a step that applies the configuration.
        config_srcs = ctx.attr.config[NogoConfigInfo].srcs
        findings = ctx.actions.declare_file(ctx.label.name + "." + arch + ".findings")
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
            toolchain = None,
        )

        # Note that this calls the filter binary without any configuration, so
        # all findings will be included. But this is expected, since we've
        # already filtered out everything that should not be included. The
        # runner will always run all tests, and then exit if any have failed.
        runner_content.append("echo -n %s..." % arch)
        runner_content.append("%s filter -test -text %s" % (ctx.files._nogo_target[0].short_path, findings.short_path))
        runner_content.append("rc_%s=$?" % arch)
        runner_footer.append("if [[ $rc_%s -ne 0 ]]; then exit $rc_%s; fi" % (arch, arch))
        all_findings.append(findings)
    runner_content.extend(runner_footer)
    runner_content.append("")  # Ensure empty line.
    ctx.actions.write(runner, "\n".join(runner_content), is_executable = True)
    return [DefaultInfo(
        # The runner just executes the filter again, on the
        # newly generated filtered findings. We still need
        # the filter tool as part of our runfiles, however.
        runfiles = ctx.runfiles(files = ctx.files._nogo_target + all_findings),
        executable = runner,
    ), OutputGroupInfo(
        # Propagate the filtered filters, for consumption by
        # build tooling. Note that the build tooling typically
        # pays attention to the mnemoic above, so this must be
        # what is expected by the tooling.
        nogo_findings = depset(all_findings),
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
        ),
        "_target": attr.label(
            default = "//tools/nogo:target",
            cfg = arch_transition,
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

def _nogo_facts_render_impl(ctx):
    """Extract nogo facts."""

    # Rendering dependency facts needs neither an import path nor an archive
    # for the package containing the template.
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
