"""Nogo rules."""

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
        "worker_debug": "transitive debugging",
    },
)

def _nogo_target_impl(ctx):
    return [NogoTargetInfo(
        goarch = ctx.attr.goarch,
        goos = ctx.attr.goos,
        worker_debug = ctx.attr.worker_debug,
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
        "worker_debug": attr.bool(
            doc = "whether worker debugging should be enabled.",
            default = False,
        ),
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
    nogo_target_info = ctx.attr._target[NogoTargetInfo]
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
        "_target": attr.label(
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
        "raw_findings": "raw package findings (if relevant)",
    },
)

def _nogo_stdlib_impl(ctx):
    # Build the standard library facts.
    nogo_target_info = ctx.attr._target[NogoTargetInfo]
    go_ctx = go_context(ctx, goos = nogo_target_info.goos, goarch = nogo_target_info.goarch)
    facts = ctx.actions.declare_file(ctx.label.name + ".facts")
    raw_findings = ctx.actions.declare_file(ctx.label.name + ".raw_findings")
    config = struct(
        Srcs = [f.path for f in go_ctx.stdlib_srcs],
        GOOS = go_ctx.goos,
        GOARCH = go_ctx.goarch,
        Tags = go_ctx.gotags,
    )
    config_file = ctx.actions.declare_file(ctx.label.name + ".cfg")
    ctx.actions.write(config_file, config.to_json())
    args_file = ctx.actions.declare_file(ctx.label.name + "_args_file")
    ctx.actions.write(
        output = args_file,
        content = "\n".join(go_ctx.nogo_args + [
            "-objdump_tool=%s" % ctx.files._objdump_tool[0].path,
            "-stdlib=%s" % config_file.path,
            "-findings=%s" % raw_findings.path,
            "-facts=%s" % facts.path,
        ]),
    )
    ctx.actions.run(
        inputs = [config_file] + go_ctx.stdlib_srcs + [args_file],
        outputs = [facts, raw_findings],
        tools = depset(go_ctx.runfiles.to_list() + ctx.files._objdump_tool),
        executable = ctx.files._check[0],
        mnemonic = "GoStandardLibraryAnalysis",
        # Note that this does not support work execution currently. There is an
        # issue with stdout pollution that is not yet resolved, so this is kept
        # as a separate menomic.
        progress_message = "Analyzing Go Standard Library",
        arguments = [
            "--worker_debug=%s" % nogo_target_info.worker_debug,
            "@%s" % args_file.path,
        ],
    )

    # Return the stdlib facts as output.
    return [NogoStdlibInfo(
        facts = facts,
        raw_findings = raw_findings,
    )]

nogo_stdlib = go_rule(
    rule,
    implementation = _nogo_stdlib_impl,
    attrs = {
        "_check": attr.label(
            default = "//tools/nogo/check:check",
            cfg = "host",
        ),
        "_objdump_tool": attr.label(
            default = "//tools/nogo:objdump_tool",
            cfg = "host",
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
        "raw_findings": "raw package findings (if relevant)",
        "importpath": "package import path",
        "binaries": "package binary files",
        "srcs": "srcs (for go_test support)",
        "deps": "deps (for go_test support)",
    },
)

def _select_objfile(files):
    """Returns (.a file, .x file, is_archive).

    If no .a file is available, then the first .x file will be returned
    instead, and vice versa. If neither are available, then the first provided
    file will be returned."""
    a_files = [f for f in files if f.path.endswith(".a")]
    x_files = [f for f in files if f.path.endswith(".x")]
    if not len(x_files) and not len(a_files):
        return (files[0], files[0], False)
    if not len(x_files):
        x_files = a_files
    if not len(a_files):
        a_files = x_files
    return a_files[0], x_files[0], True

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

    # Start with all target files and srcs as input.
    binaries = target.files.to_list()
    inputs = binaries + srcs

    # Generate a shell script that dumps the binary. Annoyingly, this seems
    # necessary as the context in which a run_shell command runs does not seem
    # to cleanly allow us redirect stdout to the actual output file. Perhaps
    # I'm missing something here, but the intermediate script does work.
    target_objfile, target_xfile, has_objfile = _select_objfile(binaries)
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
    all_raw_findings = []
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
        _, x_file, _ = _select_objfile(info.binaries)
        import_map[info.importpath] = x_file.path
        fact_map[info.importpath] = info.facts.path

        # Collect all findings; duplicates are resolved at the end.
        all_raw_findings.extend(info.raw_findings)

        # Ensure the above are available as inputs.
        inputs.append(info.facts)
        inputs += info.binaries

    # Add the module itself, for the type sanity check. This applies only to
    # the libraries, and not binaries or tests.
    if has_objfile:
        import_map[importpath] = target_xfile.path

    # Add the standard library facts.
    stdlib_info = ctx.attr._nogo_stdlib[NogoStdlibInfo]
    stdlib_facts = stdlib_info.facts
    inputs.append(stdlib_facts)

    # The nogo tool operates on a configuration serialized in JSON format.
    nogo_target_info = ctx.attr._target[NogoTargetInfo]
    go_ctx = go_context(ctx, goos = nogo_target_info.goos, goarch = nogo_target_info.goarch)
    facts = ctx.actions.declare_file(target.label.name + ".facts")
    raw_findings = ctx.actions.declare_file(target.label.name + ".raw_findings")
    config = struct(
        ImportPath = importpath,
        GoFiles = [src.path for src in srcs if src.path.endswith(".go")],
        NonGoFiles = [src.path for src in srcs if not src.path.endswith(".go")],
        GOOS = go_ctx.goos,
        GOARCH = go_ctx.goarch,
        Tags = go_ctx.gotags,
        FactMap = fact_map,
        ImportMap = import_map,
        StdlibFacts = stdlib_facts.path,
    )
    config_file = ctx.actions.declare_file(target.label.name + ".cfg")
    ctx.actions.write(config_file, config.to_json())
    inputs.append(config_file)
    args_file = ctx.actions.declare_file(ctx.label.name + "_args_file")
    ctx.actions.write(
        output = args_file,
        content = "\n".join(go_ctx.nogo_args + [
            "-binary=%s" % target_objfile.path,
            "-objdump_tool=%s" % ctx.files._objdump_tool[0].path,
            "-package=%s" % config_file.path,
            "-findings=%s" % raw_findings.path,
            "-facts=%s" % facts.path,
        ]),
    )
    ctx.actions.run(
        inputs = inputs + [args_file],
        outputs = [facts, raw_findings],
        tools = depset(go_ctx.runfiles.to_list() + ctx.files._objdump_tool),
        executable = ctx.files._check[0],
        mnemonic = "GoStaticAnalysis",
        progress_message = "Analyzing %s" % target.label,
        execution_requirements = {"supports-workers": "1"},
        arguments = [
            "--worker_debug=%s" % nogo_target_info.worker_debug,
            "@%s" % args_file.path,
        ],
    )

    # Flatten all findings from all dependencies.
    #
    # This is done because all the filtering must be done at the
    # top-level nogo_test to dynamically apply a configuration.
    # This does not actually add any additional work here, but
    # will simply propagate the full list of files.
    all_raw_findings = [stdlib_info.raw_findings] + depset(all_raw_findings).to_list() + [raw_findings]

    # Return the package facts as output.
    return [
        NogoInfo(
            facts = facts,
            raw_findings = all_raw_findings,
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
    ],
    attrs = {
        "_check": attr.label(
            default = "//tools/nogo/check:check",
            cfg = "host",
        ),
        "_objdump_tool": attr.label(
            default = "//tools/nogo:objdump_tool",
            cfg = "host",
        ),
        "_target": attr.label(
            default = "//tools/nogo:target",
            cfg = "target",
        ),
        # The name of this attribute must not be _stdlib, since that
        # appears to be reserved for some internal bazel use.
        "_nogo_stdlib": attr.label(
            default = "//tools/nogo:stdlib",
            cfg = "host",
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
    args_file = ctx.actions.declare_file(ctx.label.name + "_args_file")
    ctx.actions.write(
        output = args_file,
        content = "\n".join(
            ["-input=%s" % f.path for f in raw_findings] +
            ["-config=%s" % f.path for f in config_srcs] +
            ["-output=%s" % findings.path],
        ),
    )
    ctx.actions.run(
        inputs = raw_findings + ctx.files.srcs + config_srcs + [args_file],
        outputs = [findings],
        tools = depset(ctx.files._filter),
        executable = ctx.files._filter[0],
        mnemonic = "GoStaticAnalysis",
        progress_message = "Generating %s" % ctx.label,
        execution_requirements = {"supports-workers": "1"},
        arguments = [
            "--worker_debug=%s" % nogo_target_info.worker_debug,
            "@%s" % args_file.path,
        ],
    )

    # Build a runner that checks the filtered facts.
    #
    # Note that this calls the filter binary without any configuration, so all
    # findings will be included. But this is expected, since we've already
    # filtered out everything that should not be included.
    runner = ctx.actions.declare_file(ctx.label.name)
    runner_content = [
        "#!/bin/bash",
        "exec %s -check -input=%s" % (ctx.files._filter[0].short_path, findings.short_path),
        "",
    ]
    ctx.actions.write(runner, "\n".join(runner_content), is_executable = True)

    return [DefaultInfo(
        # The runner just executes the filter again, on the
        # newly generated filtered findings. We still need
        # the filter tool as part of our runfiles, however.
        runfiles = ctx.runfiles(files = ctx.files._filter + [findings]),
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
        "_target": attr.label(
            default = "//tools/nogo:target",
            cfg = "target",
        ),
        "_filter": attr.label(
            default = "//tools/nogo/filter:filter",
            cfg = "host",
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
