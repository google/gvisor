"""List of platforms."""

# Platform to associated tags.
platforms = {
    "ptrace": [
        # TODO(b/120560048): Make the tests run without this tag.
        "no-sandbox",
    ],
    "kvm": [
        "manual",
        "local",
        # TODO(b/120560048): Make the tests run without this tag.
        "no-sandbox",
    ],
}

default_platform = "ptrace"
