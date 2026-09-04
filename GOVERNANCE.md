# gVisor Project Governance

The gVisor project is dedicated to building an application kernel that provides
a secure isolation boundary between untrusted workloads and the host operating
system, without imposing the overhead or the operational complexity of a virtual
machine. This document explains how the project is run.

*   [Values](#values)
*   [Contributors](#contributors)
*   [Maintainers](#maintainers)
    *   [Becoming a maintainer](#becoming-a-maintainer)
    *   [Removing a maintainer](#removing-a-maintainer)
    *   [Hiatus and emeritus maintainers](#hiatus-and-emeritus-maintainers)
*   [Special Interest Groups (SIGs)](#special-interest-groups-sigs)
*   [Meetings](#meetings)
*   [Communication channels](#communication-channels)
*   [Code of Conduct](#code-of-conduct)
*   [Security Response Team](#security-response-team)
    *   [Security disclosure](#security-disclosure)
*   [Voting](#voting)
    *   [Org-balanced voting](#org-balanced-voting)
*   [When to evolve this governance](#when-to-evolve-this-governance)
*   [Modifying this charter](#modifying-this-charter)

## Values

The gVisor project and its leadership embrace the following values:

*   **Openness**: Communication and decision-making happens in the open and is
    discoverable for future reference. As much as possible, all discussions and
    work take place in public forums and open repositories.

*   **Fairness**: All stakeholders have the opportunity to provide feedback and
    submit contributions, which will be considered on their merits.

*   **Community over product or company**: Sustaining and growing our community
    takes priority over shipping code or sponsors' organizational goals. Each
    contributor participates in the project as an individual.

*   **Vendor neutrality**: The project direction and decisions are not
    controlled by any single organization. Maintainer selection, roadmap
    prioritization, and release decisions are made based on project merit, not
    employer affiliation. Maintainers hold their role as individuals, not on
    behalf of their employer, and retain it across a change of employer.

*   **Inclusivity**: We innovate through different perspectives and skill sets,
    which can only be accomplished in a welcoming and respectful environment.

*   **Participation**: Responsibilities within the project are earned through
    participation, and the path from contributor to maintainer is documented
    and open to anyone who meets it.

## Contributors

Anyone can be a *contributor* to gVisor, provided they meet the contribution
sign-off requirements and follow the rest of the
[contribution guidelines](CONTRIBUTING.md). Contributions are reviewed by a
maintainer, and must pass all applicable tests.

Reviews check for code quality and style, including documentation, and enforce
other policies. Contributions may be rejected for reasons unrelated to the code
in question. For example, a change may be too complex to maintain or duplicate
existing functionality. Where a change is rejected for such a reason, the
reviewing maintainer will say so on the change itself, in the open.

Note that contributions are not limited to code alone. Bugs, documentation,
experience reports or public advocacy are all valuable ways to contribute to the
project and build trust in the community.

## Maintainers

gVisor maintainers have approval authority on the
[project GitHub repository](https://github.com/google/gvisor). They review and
approve changes, and can assign issues and add additional reviewers. The current
maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md), which is generated
from [`governance/maintainers.yaml`](governance/maintainers.yaml). Maintainers
collectively manage the project's resources and contributors.

Any maintainer may approve a change, regardless of their affiliation, and no
change merges without a maintainer's approval.

This privilege is granted with some expectation of responsibility: maintainers
are people who care about the gVisor project and want to help it grow and
improve. A maintainer is not just someone who can make changes, but someone who
has demonstrated their ability to collaborate with the team, get the most
knowledgeable people to review code and docs, contribute high-quality code, and
follow through to fix issues (in code or tests).

Maintainers are responsible for upholding the Code of Conduct in interactions
via project communication channels. If comments or exchanges are in violation,
they may remove them at their discretion.

The collective team of all active maintainers is known as the **Maintainer
Council**, which is the governing body for the project.

### Becoming a maintainer

To become a maintainer you need to demonstrate the following:

*   commitment to the project:
    *   participate in discussions, contributions, code and documentation
        reviews for 6 months or more,
    *   perform reviews for 10 non-trivial pull requests,
    *   contribute 10 non-trivial pull requests and have them merged,
*   ability to write quality code and/or documentation,
*   ability to collaborate with the team,
*   understanding of how the team works (policies, processes for testing and
    code review, etc),
*   understanding of the project's code base and coding and documentation style.

A new maintainer must be proposed by an existing maintainer by sending a message
to the [gvisor-dev](mailto:gvisor-dev@googlegroups.com) mailing list. The
nomination is approved by a majority vote of existing maintainers, subject to
[org-balanced voting](#org-balanced-voting).

Existing maintainers will also pro-actively identify contributors who have
demonstrated a sustained track record of technical leadership and direct
contributions, rather than waiting to be asked.

Maintainer nominations will be evaluated without prejudice to employer or
demographics, and should consider the organizational diversity of the maintainer
group. Where two candidates are comparably qualified, maintainers should prefer
the candidate whose employer is less represented in the current roster.

Maintainers who are selected will be added to
[`governance/maintainers.yaml`](governance/maintainers.yaml), granted the
necessary GitHub rights, and offered access to the project's private maintainer
channels.

### Removing a maintainer

Maintainers may resign at any time if they feel that they will not be able to
continue fulfilling their project duties.

Maintainers may also be removed after being inactive, failure to fulfill their
maintainer responsibilities, violating the Code of Conduct, or other reasons.
Inactivity is defined as a period of very low or no activity in the project for
12 months or more, with no definite schedule to return to full maintainer
activity.

A maintainer may be removed at any time by a 2/3 vote of the remaining
maintainers, subject to [org-balanced voting](#org-balanced-voting).

### Hiatus and emeritus maintainers

A maintainer who steps back temporarily may be recorded as being on **hiatus**.
Maintainers on hiatus do not perform reviews but retain their permissions, and
may return to active status at any time without a vote.

A maintainer who steps back from active participation is converted to
**emeritus** status, either by request or after 12 months of inactivity.
Emeritus maintainers are recognized for their past contributions and may still
be consulted on project matters, but do not have voting rights or merge access.
Emeritus maintainers are listed in a separate section of
[MAINTAINERS.md](MAINTAINERS.md).

An emeritus maintainer may be reinstated to active maintainer status by a simple
majority vote of existing maintainers, provided they meet the current maintainer
requirements and can commit to ongoing participation.

## Special Interest Groups (SIGs)

From time to time, a SIG may be formed in order to solve larger, more complex
problems within the project. There are many avenues for collaboration outside a
SIG, but a SIG can provide structure for collaboration on a single topic.

Each group will be established by a charter approved by the Maintainer Council,
and governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Some resources may be
provided to the group, such as mailing lists or meeting space, and archives will
be public. A SIG that has become dormant may be closed by a majority vote of the
maintainers.

## Meetings

Time zones permitting, maintainers are expected to participate in the public
community meetings. Meetings are public — anyone can join — and are announced
ahead of time via the [gvisor-users](mailto:gvisor-users@googlegroups.com)
mailing list. Upcoming meetings are published on the
[community calendar](https://gvisor.dev/community/).

Maintainers will also have closed meetings in order to discuss security reports
or Code of Conduct violations. Such meetings should be scheduled by any
maintainer on receipt of a security issue or Code of Conduct report. All current
maintainers must be invited to such closed meetings, except for any maintainer
who is accused of a Code of Conduct violation.

## Communication channels

The project maintains the following channels:

*   [gvisor-users](mailto:gvisor-users@googlegroups.com): public, general
    purpose user list, used for announcements and meeting invitations.
*   [gvisor-dev](mailto:gvisor-dev@googlegroups.com): public, general purpose
    development list. Maintainer nominations and votes are held here.
*   [Gitter](https://gitter.im/gvisor/community): public chat room.
*   [GitHub issues](https://github.com/google/gvisor/issues): public bug reports
    and feature requests.
*   [gvisor-security](mailto:gvisor-security@googlegroups.com): **private**
    security list. Access is restricted to maintainers of the core gVisor
    project, subject to the [security disclosure](#security-disclosure) policy
    below. It is private so that vulnerabilities can be fixed before they are
    disclosed publicly.
*   [gvisor-syzkaller](mailto:gvisor-syzkaller@googlegroups.com): **private**
    syzkaller bug tracking list. It is private because automated fuzzing reports
    may contain undisclosed vulnerabilities. Access is not limited to
    maintainers, but will be granted to those who can credibly contribute to
    fixes.

## Code of Conduct

All participation in the gVisor project, including in the communication channels
listed above, is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

Code of Conduct violations by community members will be reported and resolved as
described in that document. Maintainers will discuss reports in private. If a
maintainer is directly involved in a report, that maintainer is excluded from
the discussion, and the remaining maintainers will designate two uninvolved
maintainers to resolve it.

## Security Response Team

The maintainers appoint a Security Response Team to handle security reports. It
currently consists of those maintainers subscribed to the
[gvisor-security](mailto:gvisor-security@googlegroups.com) list; individual
maintainers opt to participate based on need and expertise. The maintainers will
review who is assigned to this at least once a year.

The Security Response Team is responsible for handling all reports of security
holes and breaches according to the [security policy](SECURITY.md), and for the
disclosure process described below.

### Security disclosure

Security issues reach the team either through external reports to the security
list or through internal project audits. Access to the list and to audit results
is limited to the Security Response Team.

Once the team becomes aware of a potential security issue, they will assess the
scope and potential impact. If reported externally, they will determine a
reasonable embargo period with the reporter.

During the embargo period, the team will prioritize a fix for the security
issue. They may choose to disclose the issue to additional trusted contributors
in order to facilitate a fix, subjecting them to the embargo, or notify affected
users in order to give them an advanced opportunity to mitigate the issue. The
inclusion of specific users in this disclosure is left to the discretion of the
maintainers and contributors involved, and depends on the scale of known project
use and exposure.

Once a fix is widely available or the embargo period ends, the team will make
technical details about the vulnerability and associated fixes available.

Please follow the [security issue reporting rules](SECURITY.md) when reporting
security issues.

## Voting

While most business in gVisor is conducted by
"[lazy consensus](https://community.apache.org/committers/lazyConsensus.html)",
periodically the maintainers may need to vote on specific actions or changes.

A vote can be taken on the [gvisor-dev](mailto:gvisor-dev@googlegroups.com)
mailing list, or in private among the maintainers for security or conduct
matters. Votes may also be taken at a community meeting. Any maintainer may
demand a vote be taken.

Most votes require a simple majority of all active maintainers to succeed,
except where otherwise noted. Two-thirds majority votes mean at least two-thirds
of all active maintainers. Maintainers on hiatus and emeritus maintainers do not
vote and are not counted toward the total.

### Org-balanced voting

To ensure that governance decisions reflect the interests of the broader
community and not just the largest contributing organization, gVisor uses
org-balanced voting for the following decision types:

*   changes to this governance document and its supporting documents,
*   maintainer nominations, removals, and reinstatements,
*   strategic direction and roadmap prioritization,
*   official responses issued on behalf of the project.

**How it works.** Each organization (employer) gets one vote on org-balanced
decisions, regardless of how many maintainers that organization employs.
Independent contributors each receive one vote. Where a threshold is stated as a
simple or two-thirds majority, it is computed over organizational votes rather
than individual votes for these decision types.

**Determining organization.** A maintainer's organization is their current
employer as recorded in
[`governance/maintainers.yaml`](governance/maintainers.yaml) and rendered in
[MAINTAINERS.md](MAINTAINERS.md). Independent contractors and self-employed
contributors are each treated as their own organization. Companies that own one
another are treated as a single organization. If a maintainer's affiliation is
unclear, the Maintainer Council will determine it.

**Scope.** Org-balanced voting applies only to the governance decisions listed
above. Day-to-day technical decisions — pull request review, merge, and release
— continue to follow lazy consensus among maintainers, and any maintainer may
approve any change regardless of affiliation.

At the time of writing, all active gVisor maintainers are employed by a single
organization, so this section has no practical effect on current decisions. It
is adopted in advance so that the guardrail is already in place as the
maintainer base broadens, rather than having to be negotiated at the moment it
first matters.

## When to evolve this governance

The Maintainer Council model works well for focused projects with a small,
cohesive group of contributors. As the project grows, watch for these signals
that a governance transition may be needed:

*   **Decisions stall.** When the maintainer group is too large for lazy
    consensus to work, or when decisions affect subgroups differently, a
    delegation structure (working groups, SIGs) helps.
*   **New contributors cannot find a path in.** If the only path to influence is
    "become a maintainer," the project needs intermediate roles (reviewer,
    approver).
*   **A single organization dominates.** When one company holds a majority of
    maintainer seats, consider tightening the org-balanced voting rules,
    introducing company representation caps, or transitioning to an elected
    steering committee.
*   **Areas diverge.** When parts of the project develop their own contributor
    communities or release cadences, they may have become subprojects in
    practice, and federated subproject governance should be considered.

These transitions are a sign of project growth, not governance failure. The
maintainers will review this document at least annually.

## Modifying this charter

Changes to this governance document and its supporting documents may be approved
by a 2/3 vote of the maintainers, subject to
[org-balanced voting](#org-balanced-voting). Unless time is of the essence, a
proposed amendment should be circulated in the contributor community for comment
for at least one week before voting.
