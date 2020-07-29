"""Defines a rule for syscall test targets."""

load("//tools:defs.bzl", "default_platform", "loopback", "platforms")

def _runner_test_impl(ctx):
    # Generate a runner binary.
    runner = ctx.actions.declare_file("%s-runner" % ctx.label.name)
    runner_content = "\n".join([
        "#!/bin/bash",
        "set -euf -x -o pipefail",
        "if [[ -n \"${TEST_UNDECLARED_OUTPUTS_DIR}\" ]]; then",
        "  mkdir -p \"${TEST_UNDECLARED_OUTPUTS_DIR}\"",
        "  chmod a+rwx \"${TEST_UNDECLARED_OUTPUTS_DIR}\"",
        "fi",
        "exec %s %s %s\n" % (
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
        shard_count,
        size,
        platform,
        use_tmpfs,
        tags,
        network = "none",
        file_access = "exclusive",
        overlay = False,
        add_uds_tree = False,
        vfs2 = False,
        fuse = False):
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
    tags += [full_platform, "file_" + file_access]

    # Hash this target into one of 15 buckets. This can be used to
    # randomly split targets between different workflows.
    hash15 = hash(native.package_name() + name) % 15
    tags.append("hash15:" + str(hash15))

    # TODO(b/139838000): Tests using hostinet must be disabled on Guitar until
    # we figure out how to request ipv4 sockets on Guitar machines.
    if network == "host":
        tags.append("noguitar")
        tags.append("block-network")

    # Disable off-host networking.
    tags.append("requires-net:loopback")

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
    ]

    # Call the rule above.
    _runner_test(
        name = name,
        test = test,
        runner_args = runner_args,
        data = [loopback],
        size = size,
        tags = tags,
        shard_count = shard_count,
    )

def syscall_test(
        test,
        shard_count = 5,
        size = "small",
        use_tmpfs = False,
        add_overlay = False,
        add_uds_tree = False,
        add_hostinet = False,
        vfs2 = False,
        fuse = False,
        tags = None):
    """syscall_test is a macro that will create targets for all platforms.

    Args:
      test: the test target.
      shard_count: shards for defined tests.
      size: the defined test size.
      use_tmpfs: use tmpfs in the defined tests.
      add_overlay: add an overlay test.
      add_uds_tree: add a UDS test.
      add_hostinet: add a hostinet test.
      tags: starting test tags.
    """
    if not tags:
        tags = []

    _syscall_test(
        test = test,
        shard_count = shard_count,
        size = size,
        platform = "native",
        use_tmpfs = False,
        add_uds_tree = add_uds_tree,
        tags = list(tags),
    )

    for (platform, platform_tags) in platforms.items():
        _syscall_test(
            test = test,
            shard_count = shard_count,
            size = size,
            platform = platform,
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = platform_tags + tags,
        )

    vfs2_tags = list(tags)
    if vfs2:
        # Add tag to easily run VFS2 tests with --test_tag_filters=vfs2
        vfs2_tags.append("vfs2")

    else:
        # Don't automatically run tests tests not yet passing.
        vfs2_tags.append("manual")
        vfs2_tags.append("noguitar")
        vfs2_tags.append("notap")

    _syscall_test(
        test = test,
        shard_count = shard_count,
        size = size,
        platform = default_platform,
        use_tmpfs = use_tmpfs,
        add_uds_tree = add_uds_tree,
        tags = platforms[default_platform] + vfs2_tags,
        vfs2 = True,
    )

    if vfs2 and fuse:
        _syscall_test(
            test = test,
            shard_count = shard_count,
            size = size,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = platforms[default_platform] + vfs2_tags + ["fuse"],
            vfs2 = True,
            fuse = True,
        )

    # TODO(gvisor.dev/issue/1487): Enable VFS2 overlay tests.
    if add_overlay:
        _syscall_test(
            test = test,
            shard_count = shard_count,
            size = size,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = platforms[default_platform] + tags,
            overlay = True,
        )

    if add_hostinet:
        _syscall_test(
            test = test,
            shard_count = shard_count,
            size = size,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            network = "host",
            add_uds_tree = add_uds_tree,
            tags = platforms[default_platform] + tags,
        )

    if not use_tmpfs:
        # Also test shared gofer access.
        _syscall_test(
            test = test,
            shard_count = shard_count,
            size = size,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = platforms[default_platform] + tags,
            file_access = "shared",
        )
        _syscall_test(
            test = test,
            shard_count = shard_count,
            size = size,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = platforms[default_platform] + vfs2_tags,
            file_access = "shared",
            vfs2 = True,
        )
