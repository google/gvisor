"""Mutex-s rules."""

load("//tools/go_generics:defs.bzl", "go_template_instance")

def _substrs(nested_lock_names):
    substrs = {"genericMark": "prefix"}
    if nested_lock_names == None or len(nested_lock_names) == 0:
        return substrs
    quoted_names = ["\"%s\"" % (n,) for n in nested_lock_names]
    constant_names = ["Lock%s = lockNameIndex(%d)" % (n.title(), idx) for idx, n in enumerate(nested_lock_names)]
    substrs["func initLockNames() {}"] = "func initLockNames() { lockNames = []string{%s} }" % (", ".join(quoted_names),)
    substrs["/" + "/ LOCK_NAME_INDEX_CONSTANTS"] = "const (\n\t%s\n)" % ("\n\t".join(constant_names),)
    return substrs

def declare_mutex(package, name, out, prefix, nested_lock_names = None):
    go_template_instance(
        name = name,
        out = out,
        package = package,
        prefix = prefix,
        input_substrs = _substrs(nested_lock_names = nested_lock_names),
        template = "//pkg/sync/locking:generic_mutex",
    )

def declare_rwmutex(package, name, out, prefix, nested_lock_names = None):
    go_template_instance(
        name = name,
        out = out,
        package = package,
        prefix = prefix,
        input_substrs = _substrs(nested_lock_names = nested_lock_names),
        template = "//pkg/sync/locking:generic_rwmutex",
    )
