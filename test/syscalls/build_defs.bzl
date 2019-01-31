"""Defines a rule for syscall test targets."""

# syscall_test is a macro that will create targets to run the given test target
# on the host (native) and runsc.
def syscall_test(test, shard_count = 5, size = "small", use_tmpfs = False):
    _syscall_test(test, shard_count, size, "native", False)
    _syscall_test(test, shard_count, size, "kvm", use_tmpfs)
    _syscall_test(test, shard_count, size, "ptrace", use_tmpfs)
    if not use_tmpfs:
        _syscall_test(test, shard_count, size, "ptrace", use_tmpfs, "shared")

def _syscall_test(test, shard_count, size, platform, use_tmpfs, file_access = "exclusive"):
    test_name = test.split(":")[1]

    # Prepend "runsc" to non-native platform names.
    full_platform = platform if platform == "native" else "runsc_" + platform

    name = test_name + "_" + full_platform
    if file_access == "shared":
        name += "_shared"

    # Add the full_platform and file access in a tag to make it easier to run
    # all the tests on a specific flavor. Use --test_tag_filters=ptrace,file_shared.
    tags = [full_platform, "file_" + file_access]

    # Add tag to prevent the tests from running in a Bazel sandbox.
    # TODO: Make the tests run without this tag.
    tags.append("no-sandbox")

    # TODO: KVM tests are tagged "manual" to until the platform is
    # more stable.
    if platform == "kvm":
        tags += ["manual"]

    sh_test(
        srcs = ["syscall_test_runner.sh"],
        name = name,
        data = [
            ":syscall_test_runner",
            test,
        ],
        args = [
            # Arguments are passed directly to syscall_test_runner binary.
            "--test-name=" + test_name,
            "--platform=" + platform,
            "--use-tmpfs=" + str(use_tmpfs),
            "--file-access=" + file_access,
            "--parallel=true",
        ],
        size = size,
        tags = tags,
        shard_count = shard_count,
    )

def sh_test(**kwargs):
    """Wraps the standard sh_test."""
    native.sh_test(
        **kwargs
    )
