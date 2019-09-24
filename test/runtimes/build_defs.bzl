"""Defines a rule for runsc test targets."""

# runtime_test is a macro that will create targets to run the given test target
# with different runtime options.
def runtime_test(
        lang,
        image,
        shard_count = 50,
        size = "enormous"):
    sh_test(
        name = lang + "_test",
        srcs = ["runner.sh"],
        args = [
            "--lang",
            lang,
            "--image",
            image,
        ],
        data = [
            ":runner",
        ],
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
