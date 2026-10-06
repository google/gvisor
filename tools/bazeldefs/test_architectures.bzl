"""Architecture variants of maintained test declarations."""

load("@with_cfg.bzl//:with_cfg.bzl", "with_cfg")

_ARCHITECTURES = {
    "amd64": struct(
        cpu = "k8",
        constraint = Label("@platforms//cpu:x86_64"),
        platform = Label("//tools/bazeldefs:linux_amd64"),
    ),
    "arm64": struct(
        cpu = "aarch64",
        constraint = Label("@platforms//cpu:aarch64"),
        platform = Label("//tools/bazeldefs:linux_arm64"),
    ),
}

def with_test_architecture(test_rule, architecture, extra_providers = [], implicit_targets = None):
    """Returns a with_cfg builder that preserves the test's other configuration."""
    target = _ARCHITECTURES[architecture]
    return with_cfg(test_rule, extra_providers = extra_providers, implicit_targets = implicit_targets).set("cpu", target.cpu).set(
        "platforms",
        [target.platform],
    )

def test_architecture_variants(name, architectures, test_rules, kwargs):
    """Adds explicit, manual variants from the original test's complete attributes.

    Args:
        name: Original test name; variants append an architecture suffix.
        architectures: Target architectures to instantiate.
        test_rules: Architecture to configured test rule mapping.
        kwargs: Complete attributes of the original test declaration.
    """
    if len(architectures) != len(depset(architectures).to_list()):
        fail("duplicate test architectures: %s" % architectures)
    for architecture in architectures:
        if architecture not in _ARCHITECTURES:
            fail("unsupported test architecture: %s" % architecture)
        attributes = dict(kwargs)

        # Bazel runs tests in the test execution group. Preserve the caller's
        # other groups so that compiling and linking may use a different CPU.
        groups = dict(attributes.get("exec_group_compatible_with") or {})
        groups["test"] = groups.get("test", []) + [
            Label("@platforms//os:linux"),
            _ARCHITECTURES[architecture].constraint,
        ]
        attributes["exec_group_compatible_with"] = groups
        attributes["tags"] = attributes.get("tags", []) + ["manual"]
        test_rules[architecture](name = name + "_" + architecture, **attributes)
