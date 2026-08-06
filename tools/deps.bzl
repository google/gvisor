"""Rules for dependency checking."""

# DepsInfo provides a list of dependencies found when building a target.
DepsInfo = provider(
    "lists dependencies encountered while building",
    fields = {
        "nodes": "a dict from targets to a list of their dependencies",
    },
)

def _deps_check_impl(target, ctx):
    # Check the target's dependencies and add any of our own deps.
    deps = []
    if hasattr(ctx.rule.attr, "deps"):
        for dep in ctx.rule.attr.deps:
            deps.append(dep)

    nodes = {}
    if len(deps) != 0:
        nodes[target] = deps

    # Keep and propagate each dep's providers.
    if hasattr(ctx.rule.attr, "deps"):
        for dep in ctx.rule.attr.deps:
            if DepsInfo in dep:
                nodes.update(dep[DepsInfo].nodes)

    if hasattr(ctx.rule.attr, "actual_binary"):
        dep = ctx.rule.attr.actual_binary
        if dep and DepsInfo in dep:
            nodes.update(dep[DepsInfo].nodes)

            # Map target (the wrapper target) as depending on the wrapped target's deps.
            if dep in dep[DepsInfo].nodes:
                nodes[target] = dep[DepsInfo].nodes[dep]

    return [DepsInfo(nodes = nodes)]

_deps_check = aspect(
    implementation = _deps_check_impl,
    attr_aspects = ["deps", "actual_binary"],
)

def _workspace_of(label):
    # Under bzlmod, external labels have canonical workspace names like
    # "gazelle++go_deps+org_golang_x_sys".
    # Strip prefixes so that "@org_golang_x_sys//..." prefixes match.
    return label.workspace_name.rsplit("+", 1)[-1]

def _parse_prefix(prefix):
    workspace, pkg = prefix.split("//", 1)
    if len(workspace) > 0 and workspace[0] == "@":
        workspace = workspace[1:]
    return workspace, pkg

def _matches_prefix(label, prefix):
    workspace, pkg = _parse_prefix(prefix)
    return _workspace_of(label) == workspace and label.package.startswith(pkg)

def _is_allowed(target, allowlist, prefixes):
    # Check for allowed prefixes.
    for prefix in prefixes:
        if _matches_prefix(target, prefix):
            return True

    # Check the allowlist.
    for allowed in allowlist:
        if target == allowed.label:
            return True

    return False

def _check_definitely_not_allowed(ctx):
    # `deps_test` already rejects any dependency that is not explicitly
    # allowed, but this rejects additions to the allowlist itself, to make
    # it obvious at review time that something that should definitely not
    # be added is still being added. Defense in depth?
    for denied in ctx.attr.definitely_not_allowed_prefixes:
        denied_workspace, denied_pkg = _parse_prefix(denied)
        for allowed in ctx.attr.allowed:
            if _matches_prefix(allowed.label, denied):
                fail("allowed entry %s matches definitely_not_allowed_prefixes entry %s" % (allowed.label, denied))
        for prefix in ctx.attr.allowed_prefixes:
            workspace, pkg = _parse_prefix(prefix)
            if workspace == denied_workspace and (pkg.startswith(denied_pkg) or denied_pkg.startswith(pkg)):
                fail("allowed_prefixes entry %s matches definitely_not_allowed_prefixes entry %s" % (prefix, denied))

def _deps_test_impl(ctx):
    _check_definitely_not_allowed(ctx)

    nodes = {}
    for target in ctx.attr.targets:
        for (node_target, node_deps) in target[DepsInfo].nodes.items():
            # Ignore any disallowed targets. This generates more useful error
            # messages. Consider the case where A dependes on B and B depends
            # on C, and both B and C are disallowed. Avoid emitting an error
            # that B depends on C, when the real issue is that A depends on B.
            if not _is_allowed(node_target.label, ctx.attr.allowed, ctx.attr.allowed_prefixes) and node_target.label != target.label:
                continue
            bad_deps = []
            for dep in node_deps:
                if not _is_allowed(dep.label, ctx.attr.allowed, ctx.attr.allowed_prefixes):
                    bad_deps.append(dep)
            if len(bad_deps) > 0:
                nodes[node_target] = bad_deps

    # If there aren't any violations, write a passing test.
    if len(nodes) == 0:
        ctx.actions.write(
            output = ctx.outputs.executable,
            content = "#!/bin/bash\n\nexit 0\n",
        )
        return []

    # If we're here, we've found at least one violation.
    script_lines = [
        "#!/bin/bash",
        "echo Invalid dependencies found. If you\\'re sure you want to add dependencies,",
        "echo modify this target.",
        "echo",
    ]

    # List the violations.
    for target, deps in nodes.items():
        script_lines.append(
            'echo "{target} depends on:"'.format(target = target.label),
        )
        for dep in deps:
            script_lines.append('echo "\t{dep}"'.format(dep = dep.label))

    # The test must fail.
    script_lines.append("exit 1\n")

    ctx.actions.write(
        output = ctx.outputs.executable,
        content = "\n".join(script_lines),
    )
    return []

# Checks that targets only depend on an allowlist of other targets. Targets can
# be specified directly, or prefixes can be used to allow entire packages or
# directory trees.
#
# This recursively checks the "deps" attribute of each target, dependencies
# expressed other ways are not checked. For example, protobuf targets pull in
# protobuf code, but aren't analyzed by deps_test.
deps_test = rule(
    implementation = _deps_test_impl,
    attrs = {
        "targets": attr.label_list(
            doc = "The targets to check the transitive dependencies of.",
            aspects = [_deps_check],
        ),
        "allowed": attr.label_list(
            doc = "The allowed dependency targets.",
        ),
        "allowed_prefixes": attr.string_list(
            doc = "Any packages beginning with these prefixes are allowed.",
        ),
        "definitely_not_allowed_prefixes": attr.string_list(
            doc = "Packages beginning with these prefixes must not be " +
                  "covered by allowed or allowed_prefixes. Makes " +
                  "'never add these' possible to be defined explicitly in " +
                  "the BUILD file.",
        ),
    },
    test = True,
)
