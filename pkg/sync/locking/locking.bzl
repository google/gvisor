"""Mutex-s rules."""

load("//tools/go_generics:defs.bzl", "go_template_instance")

def declare_mutex(package, name, out, prefix):
    go_template_instance(
        name = name,
        out = out,
        package = package,
        prefix = prefix,
        substrs = {
            "genericMark": "prefix",
        },
        template = "//pkg/sync/locking:generic_mutex",
    )

def declare_rwmutex(package, name, out, prefix):
    go_template_instance(
        name = name,
        out = out,
        package = package,
        prefix = prefix,
        substrs = {
            "genericMark": "prefix",
        },
        template = "//pkg/sync/locking:generic_rwmutex",
    )
