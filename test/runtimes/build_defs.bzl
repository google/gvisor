"""Defines a rule for runsc test targets."""

# runtime_test is a macro that will create targets to run the given test target
# with different runtime options.
def runtime_test(
        lang,
        image,
        shard_count = 50,
        size = "enormous",
        blacklist_file = ""):
    args = [
        "--lang",
        lang,
        "--image",
        image,
    ]
    data = [
        ":runner",
    ]
    if blacklist_file != "":
        args += ["--blacklist_file", "test/runtimes/" + blacklist_file]
        data += [blacklist_file]

    sh_test(
        name = lang + "_test",
        srcs = ["runner.sh"],
        args = args,
        data = data,
        size = size,
        shard_count = shard_count,
        tags = [
            # Requires docker and runsc to be configured before the test runs.
            "manual",
            "local",
        ],
    )

def sh_test(**kwargs):
    """Wraps the standard sh_test."""
    native.sh_test(
        **kwargs
    )
