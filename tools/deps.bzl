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
    for dep in ctx.rule.attr.deps:
        deps.append(dep)
    nodes = {}
    if len(deps) != 0:
        nodes[target] = deps

    # Keep and propagate each dep's providers.
    for dep in ctx.rule.attr.deps:
        nodes.update(dep[DepsInfo].nodes)

    return [DepsInfo(nodes = nodes)]

_deps_check = aspect(
    implementation = _deps_check_impl,
    attr_aspects = ["deps"],
)

def _is_allowed(target, allowlist, prefixes):
    # Check for allowed prefixes.
    for prefix in prefixes:
        workspace, pfx = prefix.split("//", 1)
        if len(workspace) > 0 and workspace[0] == "@":
            workspace = workspace[1:]
        if target.workspace_name == workspace and target.package.startswith(pfx):
            return True

    # Check the allowlist.
    for allowed in allowlist:
        if target == allowed.label:
            return True

    return False

def _deps_test_impl(ctx):
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

# Checks that library and its deps only depends on gVisor and an allowlist of
# other dependencies.
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
    },
    test = True,
)
