"""Defines a rule for syscall test targets."""

load("//tools:defs.bzl", "default_platform", "platforms")

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
        add_uds_tree = False,
        vfs2 = False,
        fuse = False,
        **kwargs):
    # Prepend "runsc" to non-native platform names.
    full_platform = platform if platform == "native" else "runsc_" + platform

    # Name the test appropriately.
    name = test.split(":")[1] + "_" + full_platform
    if file_access == "shared":
        name += "_shared"
    if overlay:
        name += "_overlay"
    if vfs2:
        name += "_vfs2"
        if fuse:
            name += "_fuse"
    if network != "none":
        name += "_" + network + "net"

    # Apply all tags.
    if tags == None:
        tags = []

    # Add the full_platform and file access in a tag to make it easier to run
    # all the tests on a specific flavor. Use --test_tag_filters=ptrace,file_shared.
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

    container = "container" in tags

    runner_args = [
        # Arguments are passed directly to runner binary.
        "--platform=" + platform,
        "--network=" + network,
        "--use-tmpfs=" + str(use_tmpfs),
        "--file-access=" + file_access,
        "--overlay=" + str(overlay),
        "--add-uds-tree=" + str(add_uds_tree),
        "--vfs2=" + str(vfs2),
        "--fuse=" + str(fuse),
        "--strace=" + str(debug),
        "--debug=" + str(debug),
        "--container=" + str(container),
    ]

    # Call the rule above.
    _runner_test(
        name = name,
        test = test,
        runner_args = runner_args,
        tags = tags,
        **kwargs
    )

def syscall_test(
        test,
        use_tmpfs = False,
        add_overlay = False,
        add_uds_tree = False,
        add_hostinet = False,
        vfs1 = True,
        vfs2 = True,
        fuse = False,
        debug = True,
        tags = None,
        **kwargs):
    """syscall_test is a macro that will create targets for all platforms.

    Args:
      test: the test target.
      use_tmpfs: use tmpfs in the defined tests.
      add_overlay: add an overlay test.
      add_uds_tree: add a UDS test.
      add_hostinet: add a hostinet test.
      vfs1: enable VFS1 tests. Could be false only if vfs2 is true.
      vfs2: enable VFS2 support.
      fuse: enable FUSE support.
      debug: enable debug output.
      tags: starting test tags.
      **kwargs: additional test arguments.
    """
    if not tags:
        tags = []

    if vfs2 and vfs1 and not fuse:
        # Generate a vfs1 plain test. Most testing will now be
        # biased towards vfs2, with only a single vfs1 case.
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = tags + platforms[default_platform],
            debug = debug,
            vfs2 = False,
            **kwargs
        )

    if vfs1 and not fuse:
        # Generate a native test if fuse is not required.
        _syscall_test(
            test = test,
            platform = "native",
            use_tmpfs = False,
            add_uds_tree = add_uds_tree,
            tags = tags,
            debug = debug,
            **kwargs
        )

    for (platform, platform_tags) in platforms.items():
        _syscall_test(
            test = test,
            platform = platform,
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = platform_tags + tags,
            fuse = fuse,
            vfs2 = vfs2,
            debug = debug,
            **kwargs
        )

    if add_overlay:
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = platforms[default_platform] + tags,
            debug = debug,
            fuse = fuse,
            vfs2 = vfs2,
            overlay = True,
            **kwargs
        )
    if add_hostinet:
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            network = "host",
            add_uds_tree = add_uds_tree,
            tags = platforms[default_platform] + tags,
            debug = debug,
            fuse = fuse,
            vfs2 = vfs2,
            **kwargs
        )
    if not use_tmpfs:
        # Also test shared gofer access.
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = platforms[default_platform] + tags,
            debug = debug,
            file_access = "shared",
            fuse = fuse,
            vfs2 = vfs2,
            **kwargs
        )
