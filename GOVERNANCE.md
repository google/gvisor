# Governance

## Projects

A *project* is the primary unit of collaboration. Each project may have its own
repository and contribution process.

All projects are covered by the [Code of Conduct](CODE_OF_CONDUCT.md), and
should include an up-to-date copy in the project repository or a link here.

## Contributors

Anyone can be a *contributor* to a project, provided they have signed relevant
Contributor License Agreements (CLAs) and follow the project's contribution
guidelines. Contributions will be reviewed by a maintainer, and must pass all
applicable tests.

Reviews check for code quality and style, including documentation, and enforce
other policies. Contributions may be rejected for reasons unrelated to the code
in question. For example, a change may be too complex to maintain or duplicate
existing functionality.

Note that contributions are not limited to code alone. Bugs, documentation,
experience reports or public advocacy are all valuable ways to contribute to a
project and build trust in the community.

## Maintainers

Each project has one or more *maintainers*. Maintainers set technical direction,
facilitate contributions and exercise overall stewardship.

Maintainers have write access to the project repository. Maintainers review and
approve changes. They can also assign issues and add additional reviewers.

Note that some repositories may not allow direct commit access, which is
reserved for administrators or automated processes. In this case, maintainers
have approval rights, and a separate process exists for merging a change.

Maintainers are responsible for upholding the code of conduct in interactions
via project communication channels. If comments or exchanges are in violation,
they may remove them at their discretion.

### Repositories requiring synchronization

For some projects initiated by Google, the infrastructure which synchronizes and
merges internal and external changes requires that merges are performed by a
Google employee. In such cases, Google will initiate a rotation to merge changes
once they pass tests and are approved by a maintainer. This does not preclude
non-Google contributors from becoming maintainers, in which case the maintainer
holds approval rights and the merge is an automated process. In some cases,
Google-internal tests may fail and have to be fixed: the Google employee will
work with the submitter to achieve this.

### Becoming a maintainer

The list of maintainers is defined by the list of people with commit access or
approval authority on a repository, typically via a Gerrit group or a GitHub
team.

Existing maintainers may elevate a contributor to maintainer status on evidence
of previous contributions and established trust. This decision is based on lazy
consensus from existing maintainers. While contributors may ask maintainers to
make this decision, existing maintainers will also pro-actively identify
contributors who have demonstrated a sustained track record of technical
leadership and direct contributions.

## Special Interest Groups (SIGs)

From time-to-time, a SIG may be formed in order to solve larger, more complex
problems across one or more projects. There are many avenues for collaboration
outside a SIG, but a SIG can provide structure for collaboration on a single
topic.

Each group will be established by a charter, and governed by the Code of
Conduct. Some resources may be provided to the group, such as mailing lists or
meeting space, and archives will be public.

## Security disclosure

Projects may maintain security mailing lists for vulnerability reports and
internal project audits may occasionally reveal security issues. Access to these
lists and audits will be limited to project *maintainers*; individual
maintainers should opt to participate in these lists based on need and
expertise. Once maintainers become aware of a potential security issue, they
will assess the scope and potential impact. If reported externally, maintainers
will determine a reasonable embargo period with the reporter.

During the embargo period, the maintainers will prioritize a fix for the
security issue. They may choose to disclose the issue to additional trusted
contributors in order to facilitate a fix, subjecting them to the embargo, or
notify affected users in order to give them an advanced opportunity to mitigate
the issue. The inclusion of specific users in this disclosure is left to the
discretion of the maintainers and contributors involved, and depends on the
scale of known project use and exposure.

Once a fix is widely available or the embargo period ends, the maintainers will
make technical details about the vulnerability and associated fixes available.

## Mailing lists

There are four key mailing lists that span projects.

*   [gvisor-users](mailto:gvisor-users@googlegroups.com): general purpose user
    list.
*   [gvisor-dev](mailto:gvisor-dev@googlegroups.com): general purpose
    development list.
*   [gvisor-security](mailto:gvisor-security@googlegroups.com): private security
    list. Access to this list is restricted to maintainers of the core gVisor
    project, subject to the security disclosure policy described above.
*   [gvisor-syzkaller](mailto:gvisor-syzkaller@googlegroups.com): private
    syzkaller bug tracking list. Access to this list is not limited to
    maintainers, but will be granted to those who can credibly contribute to
    fixes.
