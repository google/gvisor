"""List of platforms."""

# Platform to associated tags.
platforms = {
    "ptrace": [],
    "kvm": [],
}

# Capabilities that platforms may or may not support.
# Used by platform_util.cc to determine which syscall tests are appropriate.
_CAPABILITY_32BIT = "32BIT"
_CAPABILITY_ALIGNMENT_CHECK = "ALIGNMENT_CHECK"
_CAPABILITY_MULTIPROCESS = "MULTIPROCESS"
_CAPABILITY_INT3 = "INT3"
_CAPABILITY_VSYSCALL = "VSYSCALL"

# platform_capabilities maps platform names to a dictionary of capabilities mapped to
# True (supported) or False (unsupported).
platform_capabilities = {
    "ptrace": {
        _CAPABILITY_32BIT: False,
        _CAPABILITY_ALIGNMENT_CHECK: True,
        _CAPABILITY_MULTIPROCESS: True,
        _CAPABILITY_INT3: True,
        _CAPABILITY_VSYSCALL: True,
    },
    "kvm": {
        _CAPABILITY_32BIT: False,
        _CAPABILITY_ALIGNMENT_CHECK: True,
        _CAPABILITY_MULTIPROCESS: True,
        _CAPABILITY_INT3: False,
        _CAPABILITY_VSYSCALL: True,
    },
}

default_platform = "ptrace"
