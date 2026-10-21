"""Nogo rules."""

load("//tools:arch.bzl", "arch_transition")
load("//tools/bazeldefs:go.bzl", "go_binary_archive", "go_context", "go_embed_libraries", "go_has_source", "go_importpath", "go_rule", "go_source_files", "nogo_extra_proto_deps")

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
    go_ctx = _go_context(ctx)
    args = ctx.actions.args()
    inputs, raw_findings = _nogo_config(go_ctx, args, [])

    # GOVERSION of std is set by the std go.mod.
    args.add("-GOVERSION-mod-file=%s" % go_ctx.stdlib_mod.path)

    # Build the analyzer command.
    facts_file = ctx.actions.declare_file(ctx.label.name + ".facts")
    exports = ctx.actions.declare_directory(ctx.label.name + ".exports")
    findings_file = ctx.actions.declare_file(ctx.label.name + ".raw_findings")
    stdlib_srcs = go_ctx.stdlib_srcs if type(go_ctx.stdlib_srcs) == "list" else go_ctx.stdlib_srcs.to_list()
    args.add_all([
        "bundle",
        "-export=%s" % exports.path,
        "-findings=%s" % findings_file.path,
        "-facts=%s" % facts_file.path,
        "-root=.*?/src/",
    ])
    args.add_all(stdlib_srcs)
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
        arguments = [args],
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
        "compiler_export": "compiler export data for a package without analyzed source",
        "transitive_facts": "depset of (import path, facts file) pairs",
        "raw_findings": "raw package findings (if relevant)",
        "importpath": "canonical package path",
        "source_importpath": "primary source import path for the package",
        "importpath_aliases": "alternate source import paths for the package",
        "archive": "compiled package archive for binary analyzers",
        "srcs": "srcs (for go_test support)",
        "deps": "deps (for go_test support)",
    },
)

def _go_context(ctx, attr = None):
    target = ctx.attr._target[NogoTargetInfo]
    return go_context(ctx, goos = target.goos, goarch = target.goarch, attr = attr)

def _nogo_config(go_ctx, args, deps):
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
    primary_imports = {}
    alias_imports = {}
    for dep in deps:
        # Some build rules supply only compiler archives for generated imports.
        info = dep[NogoInfo]
        compiler_imports = nogo_extra_proto_deps(dep)
        if hasattr(info, "compiler_export"):
            compiler_imports = list(compiler_imports) + [(info.importpath, info.archive, info.compiler_export)]
        for importpath, archive, export in compiler_imports:
            primary_imports.setdefault(importpath, importpath)
            args.add("-archive=%s=%s" % (importpath, archive.path))
            args.add("-compiler-import=%s=%s" % (importpath, export.path))
            inputs.extend([archive, export])

        if hasattr(info, "transitive_facts"):
            fact_sets.append(info.transitive_facts)
            raw_findings.extend(info.raw_findings)
        if not hasattr(info, "export"):
            continue

        args.add("-archive=%s=%s" % (info.importpath, info.archive.path))
        args.add("-import=%s=%s" % (info.importpath, info.export.path))
        primary_imports[info.source_importpath] = info.importpath
        for importpath in info.importpath_aliases:
            alias_imports[importpath] = info.importpath
        inputs.extend([info.archive, info.export])

    # Match rules_go's checkImports: a primary import takes precedence over
    # another dependency's alias, regardless of dependency order.
    alias_imports.update(primary_imports)
    for importpath, package_path in alias_imports.items():
        if importpath != package_path:
            args.add("-import-map=%s=%s" % (importpath, package_path))

    # Export data can expose types and methods from indirect imports. Their
    # facts must be available even without a direct source import.
    for importpath, facts_file in depset(transitive = fact_sets).to_list():
        args.add("-facts=%s=%s" % (importpath, facts_file.path))
        inputs.append(facts_file)

    return inputs, raw_findings

def _nogo_package_config(ctx, go_ctx, args, deps, importpath = None, archive = None):
    # See _nogo_config. This includes package details.
    inputs, raw_findings = _nogo_config(go_ctx, args, deps)

    # GOVERSION of packages are set by the project language version.
    args.add("-GOVERSION=%s" % go_ctx.lang_version)

    # Add the compiled package itself for analyzers that inspect object code.
    if archive != None:
        args.add("-archive=%s=%s" % (importpath, archive.path))
        inputs.append(archive)

    # Add the standard library facts.
    stdlib_info = ctx.attr._nogo_stdlib[NogoStdlibInfo]
    inputs.append(stdlib_info.exports)
    args.add("-stdlib=%s" % stdlib_info.exports.path)
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
    return inputs, raw_findings

def _archives(target):
    # Depending on the rule, the object and export data are separate .a/.x
    # files or a single archive. Executables contain neither package.
    files = target.files.to_list()
    if hasattr(target.output_groups, "compilation_outputs"):
        files.extend(target.output_groups.compilation_outputs.to_list())
    archives = [f for f in files if f.extension == "a"]
    exports = [f for f in files if f.extension == "x"]
    if not (archives or exports):
        fail("no Go package archive in outputs of %s: %s" % (target.label, files))
    return (archives or exports)[0], (exports or archives)[0]

def _nogo_aspect_impl(target, ctx):
    rule = ctx.rule
    kind = rule.kind
    deps = getattr(rule.attr, "deps", [])
    is_binary = kind in ("go_binary", "go_non_executable_binary")
    is_package = is_binary or kind in ("go_library", "go_tool_library", "go_test", "go_proto_library", "go_wrap_cc")
    if not is_package and not go_has_source(target):
        # A proto compiler contributes runtime dependencies, not Go sources.
        return [NogoInfo(deps = deps)]

    deps = list(deps)
    embeds = go_embed_libraries(rule)
    for embed in embeds:
        deps.extend(getattr(embed[NogoInfo], "deps", []))
    if not is_package:
        # A source-only embed is analyzed in its consuming package.
        return [NogoInfo(deps = deps)]

    if kind in ("go_proto_library", "go_wrap_cc") and not go_has_source(target):
        archive, export = _archives(target)
        importpath = go_importpath(target)

        # This build exposes the generated package as an archive.
        # Dependencies supplied by the proto hook are additional to it.
        infos = [dep[NogoInfo] for dep in deps if hasattr(dep[NogoInfo], "transitive_facts")]
        return [NogoInfo(
            importpath = importpath,
            archive = archive,
            compiler_export = export,
            deps = deps,
            raw_findings = ctx.attr._nogo_stdlib[NogoStdlibInfo].raw_findings + depset([f for info in infos for f in info.raw_findings]).to_list(),
            transitive_facts = depset(transitive = [info.transitive_facts for info in infos]),
        )]

    # Use the configuration of the analyzed rule, including its build tags.
    go_ctx = _go_context(ctx, rule.attr)
    if kind != "go_test" and hasattr(go_ctx, "nogo_package"):
        package, generated_deps = go_ctx.nogo_package(target, rule, NogoInfo)
        deps.extend(generated_deps)
        if not package:
            return [NogoInfo(deps = deps)]
    else:
        if is_binary:
            binary = go_binary_archive(target)
            archive = binary.file
            importpath = binary.importpath
        else:
            archive, _ = _archives(target)
            importpath = "test" if kind == "go_test" else go_importpath(target)

        # The test binary's archive is its generated main, not the package
        # under test. Use the rule's own sources with embedded sources first.
        if go_has_source(target) and kind != "go_test":
            srcs = go_source_files(target)
        else:
            srcs = list(rule.files.srcs)
            for embed in embeds:
                srcs = (go_source_files(embed) if go_has_source(embed) else getattr(embed[NogoInfo], "srcs", [])) + srcs
        package = struct(srcs = srcs, archive = archive, importpath = importpath, source_importpath = importpath, importpath_aliases = [])

    args = ctx.actions.args()
    inputs, raw_findings = _nogo_package_config(ctx, go_ctx, args, deps, package.importpath, package.archive)

    # Build the argument file, and the runner.
    facts_file = ctx.actions.declare_file(ctx.label.name + ".facts")
    export_file = ctx.actions.declare_file(ctx.label.name + ".export")
    findings_file = ctx.actions.declare_file(ctx.label.name + ".findings")
    args.add_all([
        "check",
        "-export=%s" % export_file.path,
        "-findings=%s" % findings_file.path,
        "-facts=%s" % facts_file.path,
        "-package=%s" % package.importpath,
    ])
    args.add_all(package.srcs)
    ctx.actions.run(
        inputs = inputs + package.srcs,
        outputs = [findings_file, facts_file, export_file],
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
            export = export_file,
            transitive_facts = depset(
                [(package.importpath, facts_file)],
                transitive = [
                    dep[NogoInfo].transitive_facts
                    for dep in deps
                    if hasattr(dep[NogoInfo], "transitive_facts")
                ],
            ),
            raw_findings = raw_findings + [findings_file],
            importpath = package.importpath,
            source_importpath = package.source_importpath,
            importpath_aliases = package.importpath_aliases,
            archive = package.archive,
            srcs = package.srcs,
            deps = deps,
        ),
    ]

nogo_aspect = go_rule(
    aspect,
    implementation = _nogo_aspect_impl,
    attr_aspects = ["deps", "library", "embed"],
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
    go_ctx = _go_context(ctx)
    args = ctx.actions.args()
    inputs, _ = _nogo_package_config(ctx, go_ctx, args, ctx.attr.deps)

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
