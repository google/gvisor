"""Helpers for test consistency.

These targets can be used in BUILD files in order to automatically declare a
group of targets, declare usage of those targets, and assert completeness.

For example, suppose you are declaring targets in source/BUILD that must all
be consumed in sandbox/BUILD. First declare your targets using the following
rule in source/BUILD:

  some_rule(
    name = "foo", # Existing rule.
  )

  targets(
    name = "targets",
    defined = existing_rules(),
  )

Then, whenever the target is used, add the following rule. For example, in
sandbox/BUILD add the following rule to flag the target used (*):

  targets(
    name = "foo_usage",
    covered = ["//source:foo"],
  )

Then the following rule will check that every target defined in source/BUILD
is properly consumed in sandbox/BUILD:

  targets_check(
    name = "targets_check",
    defined = ["//source:targets"]
    covered = existing_rules(),
  )

Note that these failures will all manifest at the analysis phase (i.e. as build
failures), rather than as runtime test failures. This is make this as simple and
fast to catch these inconsistencies as possible.

(*) Note that this would normally be done as part of another rule implementation,
which can emit a SyscallTargetInfo provider to note this coverage.
"""

SyscallTargetInfo = provider(
    "information about declared system call targets or coverage",
    fields = {
        "defined": "test targets defined.",
        "covered": "test targets covered.",
    },
)

def _targets_impl(ctx):
    return [SyscallTargetInfo(
        defined = ctx.attr.defined,
        covered = ctx.attr.covered,
    )]

targets = rule(
    implementation = _targets_impl,
    attrs = {
        "defined": attr.label_list(doc = "Test targets defined.", allow_empty = True),
        "covered": attr.label_list(doc = "Test targets covered.", allow_empty = True),
    },
)

def _targets_check_impl(ctx):
    # Aggregate all coverage.
    covered_labels = []
    for target in ctx.attr.covered:
        if SyscallTargetInfo in target:
            covered_labels += [
                t.label
                for t in target[SyscallTargetInfo].covered
                if not t.label in covered_labels
            ]

    # Compute ignored labels.
    ignored_labels = [target.label for target in ctx.attr.ignore]

    # Check all covered.
    for target in ctx.attr.defined:
        all_targets = target[SyscallTargetInfo].defined
        for target in all_targets:
            # If the target is not the covered labels and not ignored, fail.
            if not target.label in covered_labels and not target.label in ignored_labels:
                fail("Expected coverage of %s, not found." % target.label)

            # On the other hand, if the target *is* covered and *is* ignored, fail.
            if target.label in covered_labels and target.label in ignored_labels:
                fail("Coverage of %s is provided, but is ignored." % target.label)
    return []

targets_check = rule(
    implementation = _targets_check_impl,
    attrs = {
        "defined": attr.label_list(doc = "Targets defined.", allow_empty = True),
        "covered": attr.label_list(doc = "Targets covered.", allow_empty = True),
        "ignore": attr.label_list(doc = "Tests to ignore.", allow_empty = True),
    },
)
