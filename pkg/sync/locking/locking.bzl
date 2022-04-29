load("//tools/go_generics:defs.bzl", "go_template_instance")

def declare_mutex(pkg, name, prefix):
    go_template_instance(
        name = name,
        out = name + ".go",
        package = pkg,
        prefix = prefix,
        substrs = {
            "genericMark": "prefix",
        },
        template = "//pkg/sync/locking:generic_mutex",
    )

def declare_rwmutex(pkg, name, prefix):
    go_template_instance(
        name = name,
        out = name + ".go",
        package = pkg,
        prefix = prefix,
        substrs = {
            "genericMark": "prefix",
        },
        template = "//pkg/sync/locking:generic_rwmutex",
    )
