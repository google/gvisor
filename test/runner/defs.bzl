"""Defines a rule for syscall test targets."""

load("//tools:defs.bzl", "default_platform", "platform_capabilities", "platforms")

# Maps platform names to a GVISOR_PLATFORM_SUPPORT environment variable consumed by platform_util.cc
_platform_support_env_vars = {
    platform: ",".join(sorted([
        ("%s:%s" % (capability, "TRUE" if supported else "FALSE"))
        for capability, supported in support.items()
    ]))
    for platform, support in platform_capabilities.items()
}

def _runner_test_impl(ctx):
    # Generate a runner binary.
    runner = ctx.actions.declare_file(ctx.label.name)
    runner_content = "\n".join([
        "#!/bin/bash",
        "set -euf -x -o pipefail",
        "if [[ -n \"${TEST_UNDECLARED_OUTPUTS_DIR}\" ]]; then",
        "  mkdir -p \"${TEST_UNDECLARED_OUTPUTS_DIR}\"",
        "  chmod a+rwx \"${TEST_UNDECLARED_OUTPUTS_DIR}\"",
        "fi",
        "exec %s %s \"$@\" %s\n" % (
            ctx.files.runner[0].short_path,
            " ".join(ctx.attr.runner_args),
            ctx.files.test[0].short_path,
        ),
    ])
    ctx.actions.write(runner, runner_content, is_executable = True)

    # Return with all transitive files.
    runfiles = ctx.runfiles(
        transitive_files = depset(transitive = [
            target.data_runfiles.files
            for target in (ctx.attr.runner, ctx.attr.test)
            if hasattr(target, "data_runfiles")
        ]),
        files = ctx.files.runner + ctx.files.test,
        collect_default = True,
        collect_data = True,
    )
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

_runner_test = rule(
    attrs = {
        "runner": attr.label(
            default = "//test/runner:runner",
        ),
        "test": attr.label(
            mandatory = True,
        ),
        "runner_args": attr.string_list(),
        "data": attr.label_list(
            allow_files = True,
        ),
    },
    test = True,
    implementation = _runner_test_impl,
)

def _syscall_test(
        test,
        platform,
        use_tmpfs,
        tags,
        debug,
        network = "none",
        file_access = "exclusive",
        overlay = False,
        add_host_communication = False,
        container = None,
        one_sandbox = True,
        **kwargs):
    # Prepend "runsc" to non-native platform names.
    full_platform = platform if platform == "native" else "runsc_" + platform

    # Name the test appropriately.
    name = test.split(":")[1] + "_" + full_platform
    if file_access == "shared":
        name += "_shared"
    if overlay:
        name += "_overlay"
    if network != "none":
        name += "_" + network + "net"

    # Apply all tags.
    if tags == None:
        tags = []

    # Add the full_platform and file access in a tag to make it easier to run
    # all the tests on a specific flavor. Use --test_tag_filters=runsc_ptrace,file_shared.
    tags = list(tags)
    tags += [full_platform, "file_" + file_access]

    # Hash this target into one of 15 buckets. This can be used to
    # randomly split targets between different workflows.
    hash15 = hash(native.package_name() + name) % 15
    tags.append("hash15:" + str(hash15))
    tags.append("hash15")

    # Disable off-host networking.
    tags.append("requires-net:loopback")
    tags.append("requires-net:ipv4")
    tags.append("block-network")

    # gotsan makes sense only if tests are running in gVisor.
    if platform == "native":
        tags.append("nogotsan")

    if container == None:
        # Containerize in the following cases:
        #  - "container" is explicitly specified as a tag
        #  - Running tests natively
        #  - Running tests with host networking
        container = "container" in tags or network == "host"

    if platform == "native":
        # The "native" platform supports everything.
        platform_support = ",".join(sorted([
            ("%s:TRUE" % key)
            for key in platform_capabilities[default_platform].keys()
        ]))
    else:
        platform_support = _platform_support_env_vars.get(platform, "")

    runner_args = [
        # Arguments are passed directly to runner binary.
        "--platform=" + platform,
        "--platform-support=" + platform_support,
        "--network=" + network,
        "--use-tmpfs=" + str(use_tmpfs),
        "--file-access=" + file_access,
        "--overlay=" + str(overlay),
        "--add-host-communication=" + str(add_host_communication),
        "--strace=" + str(debug),
        "--debug=" + str(debug),
        "--container=" + str(container),
        "--one-sandbox=" + str(one_sandbox),
    ]

    # Trace points are platform agnostic, so enable them for ptrace only.
    if platform == "ptrace":
        runner_args.append("--trace")

    # Call the rule above.
    _runner_test(
        name = name,
        test = test,
        runner_args = runner_args,
        tags = tags,
        **kwargs
    )

def all_platforms():
    """All platforms returns a list of all platforms."""
    available = dict(platforms.items())
    available[default_platform] = platforms.get(default_platform, [])
    return available.items()

def syscall_test(
        test,
        use_tmpfs = False,
        add_overlay = False,
        add_host_communication = False,
        add_hostinet = False,
        one_sandbox = True,
        allow_native = True,
        debug = True,
        container = None,
        tags = None,
        **kwargs):
    """syscall_test is a macro that will create targets for all platforms.

    Args:
      test: the test target.
      use_tmpfs: use tmpfs in the defined tests.
      add_overlay: add an overlay test.
      add_host_communication: setup UDS and pipe external communication for tests.
      add_hostinet: add a hostinet test.
      one_sandbox: runs each unit test in a new sandbox instance.
      allow_native: generate a native test variant.
      debug: enable debug output.
      container: Run the test in a container. If None, determined from other information.
      tags: starting test tags.
      **kwargs: additional test arguments.
    """
    if not tags:
        tags = []

    if allow_native:
        _syscall_test(
            test = test,
            platform = "native",
            use_tmpfs = False,
            add_host_communication = add_host_communication,
            tags = tags,
            debug = debug,
            container = container,
            one_sandbox = one_sandbox,
            **kwargs
        )

    for platform, platform_tags in all_platforms():
        _syscall_test(
            test = test,
            platform = platform,
            use_tmpfs = use_tmpfs,
            add_host_communication = add_host_communication,
            tags = platform_tags + tags,
            debug = debug,
            container = container,
            one_sandbox = one_sandbox,
            **kwargs
        )

    if add_overlay:
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_host_communication = add_host_communication,
            tags = platforms.get(default_platform, []) + tags,
            debug = debug,
            container = container,
            one_sandbox = one_sandbox,
            overlay = True,
            **kwargs
        )
    if add_hostinet:
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            network = "host",
            add_host_communication = add_host_communication,
            tags = platforms.get(default_platform, []) + tags,
            debug = debug,
            container = container,
            one_sandbox = one_sandbox,
            **kwargs
        )
    if not use_tmpfs:
        # Also test shared gofer access.
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_host_communication = add_host_communication,
            tags = platforms.get(default_platform, []) + tags,
            debug = debug,
            container = container,
            one_sandbox = one_sandbox,
            file_access = "shared",
            **kwargs
        )
