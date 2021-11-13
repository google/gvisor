"""List of special Go suffixes."""

def explode(tagset, suffixes):
    """explode combines tagset and suffixes in all ways.

    Args:
      tagset: Original suffixes.
      suffixes: Suffixes to combine before and after.

    Returns:
      The set of possible combinations.
    """
    result = [t for t in tagset]
    result += [s for s in suffixes]
    for t in tagset:
        result += [t + s for s in suffixes]
        result += [s + t for s in suffixes]
    return result

archs = [
    "_386",
    "_aarch64",
    "_amd64",
    "_arm",
    "_arm64",
    "_mips",
    "_mips64",
    "_mips64le",
    "_mipsle",
    "_ppc64",
    "_ppc64le",
    "_riscv64",
    "_s390x",
    "_sparc64",
    "_x86",

    # Pseudo-architectures to group by word side.
    "_32bit",
    "_64bit",
]

oses = [
    "_linux",

    # Pseudo-OS that effectively means "everything but Windows."
    "_unix",
]

generic = [
    "_impl",
    "_race",
    "_norace",
    "_unsafe",
    "_opts",
]

# State explosion? Sure. This is approximately:
#   len(archs) * (1 + 2 * len(oses) * (1 + 2 * len(generic))
#
# This evaluates to 495 at the time of writing. So it's a lot of different
# combinations, but not so much that it will cause issues. We can probably add
# quite a few more variants before this becomes a genuine problem.
go_suffixes = explode(explode(archs, oses), generic)
