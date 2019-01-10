"""Defines a rule for syscall test targets."""

# syscall_test is a macro that will create targets to run the given test target
# on the host (native) and runsc.
def syscall_test(test, shard_count = 5, size = "small"):
    _syscall_test(test, shard_count, size, "native")
    _syscall_test(test, shard_count, size, "kvm")
    _syscall_test(test, shard_count, size, "ptrace")

def _syscall_test(test, shard_count, size, platform):
    test_name = test.split(":")[1]

    # Prepend "runsc" to non-native platform names.
    full_platform = platform if platform == "native" else "runsc_" + platform

    # Add the full_platform in a tag to make it easier to run all the tests on
    # a specific platform.
    tags = [full_platform]

    # Add tag to prevent the tests from running in a Bazel sandbox.
    # TODO: Make the tests run without this tag.
    tags.append("no-sandbox")

    # TODO: KVM tests are tagged "manual" to until the platform is
    # more stable.
    if platform == "kvm":
        tags += ["manual"]

    sh_test(
        srcs = ["syscall_test_runner.sh"],
        name = test_name + "_" + full_platform,
        data = [
            ":syscall_test_runner",
            test,
        ],
        args = [
            # Arguments are passed directly to syscall_test_runner binary.
            "--test-name=" + test_name,
            "--platform=" + platform,
            "--debug=false",
            "--strace=false",
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
