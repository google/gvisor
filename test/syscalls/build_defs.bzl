"""Defines a rule for syscall test targets."""

# syscall_test is a macro that will create targets to run the given test target
# on the host (native) and runsc.
def syscall_test(
        test,
        shard_count = 5,
        size = "small",
        use_tmpfs = False,
        add_overlay = False,
        add_uds_tree = False,
        add_hostinet = False,
        tags = None):
    _syscall_test(
        test = test,
        shard_count = shard_count,
        size = size,
        platform = "native",
        use_tmpfs = False,
        add_uds_tree = add_uds_tree,
        tags = tags,
    )

    _syscall_test(
        test = test,
        shard_count = shard_count,
        size = size,
        platform = "kvm",
        use_tmpfs = use_tmpfs,
        add_uds_tree = add_uds_tree,
        tags = tags,
    )

    _syscall_test(
        test = test,
        shard_count = shard_count,
        size = size,
        platform = "ptrace",
        use_tmpfs = use_tmpfs,
        add_uds_tree = add_uds_tree,
        tags = tags,
    )

    if add_overlay:
        _syscall_test(
            test = test,
            shard_count = shard_count,
            size = size,
            platform = "ptrace",
            use_tmpfs = False,  # overlay is adding a writable tmpfs on top of root.
            add_uds_tree = add_uds_tree,
            tags = tags,
            overlay = True,
        )

    if not use_tmpfs:
        # Also test shared gofer access.
        _syscall_test(
            test = test,
            shard_count = shard_count,
            size = size,
            platform = "ptrace",
            use_tmpfs = use_tmpfs,
            add_uds_tree = add_uds_tree,
            tags = tags,
            file_access = "shared",
        )

    if add_hostinet:
        _syscall_test(
            test = test,
            shard_count = shard_count,
            size = size,
            platform = "ptrace",
            use_tmpfs = use_tmpfs,
            network = "host",
            add_uds_tree = add_uds_tree,
            tags = tags,
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
        add_uds_tree = False):
    test_name = test.split(":")[1]

    # Prepend "runsc" to non-native platform names.
    full_platform = platform if platform == "native" else "runsc_" + platform

    name = test_name + "_" + full_platform
    if file_access == "shared":
        name += "_shared"
    if overlay:
        name += "_overlay"
    if network != "none":
        name += "_" + network + "net"

    if tags == None:
        tags = []

    # Add the full_platform and file access in a tag to make it easier to run
    # all the tests on a specific flavor. Use --test_tag_filters=ptrace,file_shared.
    tags += [full_platform, "file_" + file_access]

    # Add tag to prevent the tests from running in a Bazel sandbox.
    # TODO(b/120560048): Make the tests run without this tag.
    tags.append("no-sandbox")

    # TODO(b/112165693): KVM tests are tagged "manual" to until the platform is
    # more stable.
    if platform == "kvm":
        tags += ["manual"]
        tags += ["requires-kvm"]

    args = [
        # Arguments are passed directly to syscall_test_runner binary.
        "--test-name=" + test_name,
        "--platform=" + platform,
        "--network=" + network,
        "--use-tmpfs=" + str(use_tmpfs),
        "--file-access=" + file_access,
        "--overlay=" + str(overlay),
        "--add-uds-tree=" + str(add_uds_tree),
    ]

    sh_test(
        srcs = ["syscall_test_runner.sh"],
        name = name,
        data = [
            ":syscall_test_runner",
            test,
        ],
        args = args,
        size = size,
        tags = tags,
        shard_count = shard_count,
    )

def sh_test(**kwargs):
    """Wraps the standard sh_test."""
    native.sh_test(
        **kwargs
    )

def select_for_linux(for_linux, for_others = []):
    return for_linux
