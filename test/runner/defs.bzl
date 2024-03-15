"""Defines a rule for syscall test targets."""

load("//tools:defs.bzl", "default_platform", "platform_capabilities", "platforms", "save_restore_platforms")

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
        add_host_uds = False,
        add_host_connector = False,
        add_host_fifo = False,
        iouring = False,
        container = None,
        one_sandbox = True,
        fusefs = False,
        directfs = False,
        leak_check = False,
        save = False,
        save_resume = False,
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
    if fusefs:
        name += "_fuse"
    if directfs:
        name += "_directfs"
    if save:
        name += "_save"
    if save_resume:
        name += "_save_resume"

    # Apply all tags.
    if tags == None:
        tags = []

    # Add the full_platform and file access in a tag to make it easier to run
    # all the tests on a specific flavor. Use --test_tag_filters=runsc_systrap,file_shared.
    tags = list(tags)
    tags += [full_platform, "file_" + file_access]

    if save or save_resume:
        tags.append("allsave")
        if platform in save_restore_platforms:
            if save:
                tags.append("save_restore")
            if save_resume:
                tags.append("save_resume")

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
        "--fusefs=" + str(fusefs),
        "--file-access=" + file_access,
        "--overlay=" + str(overlay),
        "--add-host-uds=" + str(add_host_uds),
        "--add-host-connector=" + str(add_host_connector),
        "--add-host-fifo=" + str(add_host_fifo),
        "--strace=" + str(debug),
        "--debug=" + str(debug),
        "--container=" + str(container),
        "--one-sandbox=" + str(one_sandbox),
        "--iouring=" + str(iouring),
        "--directfs=" + str(directfs),
        "--leak-check=" + str(leak_check),
        "--save=" + str(save),
        "--save-resume=" + str(save_resume),
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

def syscall_test_variants(
        test,
        use_tmpfs = False,
        add_fusefs = False,
        add_overlay = False,
        add_host_uds = False,
        add_host_connector = False,
        add_host_fifo = False,
        add_hostinet = False,
        add_directfs = True,
        one_sandbox = True,
        iouring = False,
        allow_native = True,
        leak_check = True,
        debug = True,
        container = None,
        tags = None,
        save = False,
        save_resume = False,
        size = "medium",
        timeout = None,
        **kwargs):
    """Generates syscall tests for all variants.

    Args:
      test: the test target.
      use_tmpfs: use tmpfs in the defined tests.
      add_fusefs: add a fusefs test.
      add_overlay: add an overlay test.
      add_host_uds: setup bound UDS on the host.
      add_host_connector: setup host threads to connect to bound UDS created by sandbox.
      add_host_fifo: setup FIFO files on the host.
      add_hostinet: add a hostinet test.
      add_directfs: add a directfs test.
      one_sandbox: runs each unit test in a new sandbox instance.
      iouring: enable IO_URING support.
      allow_native: generate a native test variant.
      debug: enable debug output.
      container: Run the test in a container. If None, determined from other information.
      tags: starting test tags.
      leak_check: enables leak check.
      save: save restore test.
      size: test size.
      timeout: timeout for the test.
      save_resume: save resume test.
      **kwargs: additional test arguments.
    """
    for platform, platform_tags in all_platforms():
        # Add directfs to the default platform variant.
        directfs = add_directfs and platform == default_platform
        _syscall_test(
            test = test,
            platform = platform,
            use_tmpfs = use_tmpfs,
            add_host_uds = add_host_uds,
            add_host_connector = add_host_connector,
            add_host_fifo = add_host_fifo,
            tags = platform_tags + tags,
            iouring = iouring,
            directfs = directfs,
            debug = debug,
            container = container,
            one_sandbox = one_sandbox,
            leak_check = leak_check,
            save = save,
            save_resume = save_resume,
            size = size,
            timeout = timeout,
            **kwargs
        )

    if add_overlay:
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_host_uds = add_host_uds,
            add_host_connector = add_host_connector,
            add_host_fifo = add_host_fifo,
            tags = platforms.get(default_platform, []) + tags,
            debug = debug,
            iouring = iouring,
            container = container,
            one_sandbox = one_sandbox,
            overlay = True,
            leak_check = leak_check,
            save = save,
            size = size,
            save_resume = save_resume,
            timeout = timeout,
            **kwargs
        )

    # TODO(b/192114729): hostinet is not supported with S/R.
    if add_hostinet and not (save or save_resume):
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            network = "host",
            add_host_uds = add_host_uds,
            add_host_connector = add_host_connector,
            add_host_fifo = add_host_fifo,
            tags = platforms.get(default_platform, []) + tags,
            debug = debug,
            iouring = iouring,
            container = container,
            one_sandbox = one_sandbox,
            leak_check = leak_check,
            save = save,
            save_resume = save_resume,
            size = size,
            timeout = timeout,
            **kwargs
        )
    if not use_tmpfs:
        # Also test shared gofer access.
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = use_tmpfs,
            add_host_uds = add_host_uds,
            add_host_connector = add_host_connector,
            add_host_fifo = add_host_fifo,
            tags = platforms.get(default_platform, []) + tags,
            iouring = iouring,
            debug = debug,
            container = container,
            one_sandbox = one_sandbox,
            file_access = "shared",
            leak_check = leak_check,
            save = save,
            save_resume = save_resume,
            size = size,
            timeout = timeout,
            **kwargs
        )
    if add_fusefs:
        _syscall_test(
            test = test,
            platform = default_platform,
            use_tmpfs = True,
            fusefs = True,
            add_host_uds = add_host_uds,
            add_host_connector = add_host_connector,
            add_host_fifo = add_host_fifo,
            tags = platforms.get(default_platform, []) + tags,
            debug = debug,
            container = container,
            one_sandbox = one_sandbox,
            leak_check = leak_check,
            save = save,
            size = size,
            save_resume = save_resume,
            timeout = timeout,
            **kwargs
        )

def syscall_test(
        test,
        use_tmpfs = False,
        add_fusefs = False,
        add_overlay = False,
        add_host_uds = False,
        add_host_connector = False,
        add_host_fifo = False,
        add_hostinet = False,
        add_directfs = True,
        one_sandbox = True,
        iouring = False,
        allow_native = True,
        leak_check = True,
        debug = True,
        container = None,
        tags = None,
        save = True,
        save_resume = True,
        size = "medium",
        **kwargs):
    """syscall_test is a macro that will create targets for all platforms.

    Args:
      test: the test target.
      use_tmpfs: use tmpfs in the defined tests.
      add_fusefs: add a fusefs test.
      add_overlay: add an overlay test.
      add_host_uds: setup bound UDS on the host.
      add_host_connector: setup host threads to connect to bound UDS created by sandbox.
      add_host_fifo: setup FIFO files on the host.
      add_hostinet: add a hostinet test.
      add_directfs: add a directfs test.
      one_sandbox: runs each unit test in a new sandbox instance.
      iouring: enable IO_URING support.
      allow_native: generate a native test variant.
      debug: enable debug output.
      container: Run the test in a container. If None, determined from other information.
      tags: starting test tags.
      leak_check: enables leak check.
      save: save restore test.
      save_resume: save resume test.
      size: test size.
      **kwargs: additional test arguments.
    """
    if not tags:
        tags = []

    if allow_native:
        _syscall_test(
            test = test,
            platform = "native",
            use_tmpfs = False,
            add_host_uds = add_host_uds,
            add_host_connector = add_host_connector,
            add_host_fifo = add_host_fifo,
            tags = tags,
            iouring = iouring,
            debug = debug,
            container = container,
            one_sandbox = one_sandbox,
            **kwargs
        )

    syscall_test_variants(
        test,
        use_tmpfs,
        add_fusefs,
        add_overlay,
        add_host_uds,
        add_host_connector,
        add_host_fifo,
        add_hostinet,
        add_directfs,
        one_sandbox,
        iouring,
        allow_native,
        leak_check,
        debug,
        container,
        tags,
        False,  # save, generate all tests without save variant.
        False,  # save_resume, generate all tests without save_resume variant.
        size,
        **kwargs
    )

    # Add save variant to all other variants generated above.
    if save:
        # Disable go sanitizers for save tests.
        tags.append("nogotsan")
        syscall_test_variants(
            test,
            use_tmpfs,
            add_fusefs,
            add_overlay,
            add_host_uds,
            add_host_connector,
            add_host_fifo,
            add_hostinet,
            add_directfs,
            one_sandbox,
            iouring,
            allow_native,
            leak_check,
            debug,
            container,
            tags,
            True,  # save, generate all tests with save variant.
            False,  # save_resume, generate all tests without save_resume variant.
            "large",  # size, use size as large by default for all S/R tests.
            "long",  # timeout, use long timeout for S/R tests.
            **kwargs
        )

    # Add save resume variant to all other variants generated above.
    if save_resume:
        syscall_test_variants(
            test,
            use_tmpfs,
            add_fusefs,
            add_overlay,
            add_host_uds,
            add_host_connector,
            add_host_fifo,
            add_hostinet,
            add_directfs,
            one_sandbox,
            iouring,
            allow_native,
            leak_check,
            debug,
            container,
            tags,
            False,  # save, generate all tests without save variant.
            True,  # save_resume, generate all tests with save_resume variant.
            "large",  # size, use size as large by default for all S/R tests.
            "long",  # timeout, use long timeout for S/R tests.
            **kwargs
        )
