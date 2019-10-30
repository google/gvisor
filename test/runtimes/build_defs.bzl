"""Defines a rule for runtime test targets."""

load("@io_bazel_rules_go//go:def.bzl", "go_test")

def runtime_test(
        name,
        lang,
        image_repo = "gcr.io/gvisor-presubmit",
        image_name = None,
        blacklist_file = None,
        shard_count = 50,
        size = "enormous"):
    """Generates sh_test and blacklist test targets for a given runtime.

    Args:
      name: The name of the runtime being tested. Typically, the lang + version.
          This is used in the names of the generated test targets.
      lang: The language being tested.
      image_repo: The docker repository containing the proctor image to run.
          i.e., the prefix to the fully qualified docker image id.
      image_name: The name of the image in the image_repo.
          Defaults to the test name.
      blacklist_file: A test blacklist to pass to the runtime test's runner.
      shard_count: See Bazel common test attributes.
      size: See Bazel common test attributes.
    """
    if image_name == None:
        image_name = name
    args = [
        "--lang",
        lang,
        "--image",
        "/".join([image_repo, image_name]),
    ]
    data = [
        ":runner",
    ]
    if blacklist_file:
        args += ["--blacklist_file", "test/runtimes/" + blacklist_file]
        data += [blacklist_file]

        # Add a test that the blacklist parses correctly.
        blacklist_test(name, blacklist_file)

    sh_test(
        name = name + "_test",
        srcs = ["runner.sh"],
        args = args,
        data = data,
        size = size,
        shard_count = shard_count,
        tags = [
            # Requires docker and runsc to be configured before the test runs.
            "local",
        ],
    )

def blacklist_test(name, blacklist_file):
    """Test that a blacklist parses correctly."""
    go_test(
        name = name + "_blacklist_test",
        embed = [":runner"],
        srcs = ["blacklist_test.go"],
        args = ["--blacklist_file", "test/runtimes/" + blacklist_file],
        data = [blacklist_file],
    )

def sh_test(**kwargs):
    """Wraps the standard sh_test."""
    native.sh_test(
        **kwargs
    )
