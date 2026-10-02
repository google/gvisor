# gVisor Releases

This document has two parts:

-   [Release policy](#release-policy), for users: versions, cadence, where to
    get a release, and the backport policy.
-   [Release process](#release-process), for maintainers: how to make a
    release, and the playbooks to follow.

## Release policy

### Versions

A release has a name of the form `release-<yyyymmdd>.<N>`, for example
`release-20261005.0`.

-   `<yyyymmdd>` is the date of the release branch. It is the Monday of the
    week in which the release was cut. The release is usually published
    some days later.
-   `<N>` is the point release number. The first release for a date is `.0`. A
    point release (`.1`, `.2`, ...) adds fixes to the release of that date.

A higher version is a newer release: `20261005.0` is newer than `20260928.1`,
even if `20260928.1` was published later.

### Cadence

gVisor makes a release every week. Each release is cut from the `master` branch.

gVisor does not have long-term support (LTS) releases. Use the newest release.
Fixes go to `master` and come in the next weekly release.

### Where to get a release

The release bucket and the apt repository are the canonical channels. The
[GitHub releases](https://github.com/google/gvisor/releases) page has a copy of
the same artifacts. See [Installation](g3doc/user_guide/install.md) for the
channels (latest, specific release, point release, nightly, and HEAD) and the
install commands.

`latest`, the apt `release` suite, and the "Latest" label on GitHub always point
to the highest version. A backport to an older date does not change them.

Each artifact has a `.sha512` file next to it. The GitHub release also has
`SHA256SUMS` and `SHA512SUMS`. Check the digest before you install.

### Backport policy

A backport puts a fix on a published release. The result is a point release,
for example `20261005.1`. gVisor backports a fix only for a security issue:

-   The issue crosses the sandbox boundary. See [SECURITY.md](SECURITY.md).
-   The issue is a security issue in the newest release.

gVisor does not backport other bug fixes or new features. These come in the next
weekly release.

A security fix is always backported to the newest release, because most users
install the latest release. A fix is backported to an older date only when users
pin that date. If you pin a date, use the specific release channel for that
date, so that you get its backports.

### Security issues and embargoes

Report a vulnerability as described in [SECURITY.md](SECURITY.md).

If a fix is under embargo, it stays private until a date agreed with the
reporter. On that date, the fix goes to `master`, and the backports are released
some hours later, when the build is done. The security advisory is published
with the release.

## Release process

This part is for gVisor maintainers.

### Principle

The release branch holds the code for one release. The release tag comes from
that branch.

The commit is the input of a release, not a result. The maintainer who starts a
release chooses the commit when they cut the branch. The branch moves only when
a gVisor maintainer moves it.

A release branch has a short life. You cut it, you cherry-pick changes to it,
and you publish it. After that it is inert. The only exception is a security
backport (see [Backports](#backports)).

### Sequence

Step                      | Who                                  | Result
------------------------- | ------------------------------------ | ------
1. Cut                    | A maintainer                         | `release/<yyyymmdd>` at one commit on master
2. Cherry-pick (optional) | A maintainer                         | Cherry-picks from master, merged to the branch by pull request
3. Stage                  | A maintainer, with a GitHub workflow | Tag `release-<yyyymmdd>.<N>-staging` on the branch head
4. Publish                | Buildkite                            | Artifacts in `gs://gvisor/releases/`, then tag `release-<yyyymmdd>.<N>`
5. Mirror                 | GitHub workflow                      | GitHub release with the artifacts and release notes

All cherry-picks go to the branch before step 3. After step 3, the branch does
not change, except for a backport.

### Backports

A backport puts a fix on a published release and makes a point release, for
example `20260928.1`. Make one only if the [backport policy](#backport-policy)
allows it. Otherwise,
merge the fix to master and let the next weekly release get it.

1.  Always merge the fix to master first. The workflows refuse a commit that is
    not on master.
2.  Backport to the newest release if it does not have the fix.
3.  Backport to an older release only if users pin that date.
4.  For a vulnerability, obey the [embargo](#embargo) rules.

### Embargo

An embargo is an agreement with the reporter: the fix stays private until an
agreed date. GitHub supplies the private workspace (a draft security advisory
and its temporary private fork), and gVisor uses it.

Before the embargo date:

-   Do the work only in the private fork of the advisory.
-   Do not push a branch, open a pull request, or run a release workflow in
    `google/gvisor`. All of these are public.

On the embargo date:

1.  Merge the fix from the advisory to master.
2.  Backport the fix and stage the releases
    ([Playbook C](#playbook-c-security-backport)).
3.  Publish the advisory when the release is published.

The fix becomes public when it merges to master. The release follows some hours
later, because the build takes time. Tell the reporter about this gap when you
agree on the date.

Only repository admins and security managers can create advisories. Give release
maintainers the security manager role.

### Playbook A: GitHub Actions

Start each workflow from **Actions → *workflow name* → Run workflow**. The **Use
workflow from** branch is the target branch.

#### A1. Cut

1.  Open **Cut Release Branch**.
2.  Set **Use workflow from** to `master`.
3.  Leave `commit` empty to use the head of master, or enter a commit on master.
4.  Click **Run workflow**.
5.  Make sure that the run summary shows `Cut release/<yyyymmdd> at <commit>`.

#### A2. Cherry-pick (optional)

1.  Merge each fix to master first.
2.  Open **Cherry-pick to Release Branch**.
3.  Set **Use workflow from** to `release/<yyyymmdd>`.
4.  In `commits`, enter the master commits, oldest first, separated by spaces.
5.  Click **Run workflow**. Open the pull request link in the run summary.
6.  Review the pull request and merge it. Use "Create a merge commit" or "Rebase
    and merge", not "Squash and merge".
7.  If a commit has conflicts, the run stops and lists the files. Do that
    cherry-pick by hand ([B2](#b2-cherry-pick-optional)).

#### A3. Stage

1.  Make sure that all cherry-pick pull requests are merged.
2.  Open **Stage Release**.
3.  Set **Use workflow from** to `release/<yyyymmdd>`.
4.  In `version`, enter `<yyyymmdd>.0`.
5.  Click **Run workflow**.

#### A4. Verify the publish

1.  Open
    `https://buildkite.com/gvisor/release/builds?branch=release-<version>-staging`.
    Make sure that the build started. If it did not, see
    [Troubleshooting](#troubleshooting).
2.  When the build passes, make sure that:
    -   The tag `release-<version>` exists, and the staging tag does not.
    -   `https://storage.googleapis.com/gvisor/releases/release/<version>/x86_64/gvisor.tar.zstd`
        exists. Do the same check for `aarch64`.
    -   The **Release Mirror** run passed, and the GitHub release exists.
    -   If this is the highest version, the GitHub release has the "Latest"
        label.

### Playbook B: Command line

Use this playbook only if GitHub Actions is not available. You must have push
access to `google/gvisor`, and `origin` must point to it. These steps do not run
the workflow checks, so do each check yourself.

```bash
git fetch origin --tags
date=20261005            # The Monday of this week.
```

#### B1. Cut

```bash
commit="$(git rev-parse origin/master)"       # Or a chosen commit on master.
git merge-base --is-ancestor "${commit}" origin/master && echo "On master."
git ls-remote --exit-code origin "refs/heads/release/${date}" && echo "STOP: the branch exists."
git tag -l "release-${date}.*"                # Must be empty.
git push origin "${commit}:refs/heads/release/${date}"
```

#### B2. Cherry-pick (optional)

You can push the cherry-pick branch to your fork.

```bash
git switch -c "cherry-pick/${date}-<topic>" "origin/release/${date}"
git cherry-pick -x <sha>                      # Add "-m 1" for a merge commit.
git push <your-remote> HEAD
gh pr create --repo google/gvisor --base "release/${date}" \
  --head "<you>:cherry-pick/${date}-<topic>"
```

Get a review, then merge the pull request.

#### B3. Stage

```bash
git fetch origin --tags
commit="$(git rev-parse "origin/release/${date}")"
git tag --points-at "${commit}" -l 'release-*' # Must be empty.
echo "Release ${date}.0" >/tmp/msg
tools/tag_release.sh "${commit}" "${date}.0" /tmp/msg
```

This is the same as `make tag RELEASE_COMMIT="${commit}"
RELEASE_NAME="${date}.0" RELEASE_NOTES=/tmp/msg`.

#### B4. Verify

Do the steps in [A4](#a4-verify-the-publish).

### Playbook C: Security backport

Do this playbook only if the
[backport policy](#backport-policy) allows it. For
an embargoed fix, start on the embargo date.

1.  Merge the fix to master.
2.  Find the releases that need the fix:
    -   The newest release. Run cherry-pick on its branch. If the branch already
        has the fix, the run stops with "already on release/...".
    -   Older releases, only if users pin them.
3.  For each branch, do [A2](#a2-cherry-pick-optional) and merge the pull request.
4.  For each branch, do [A3](#a3-stage) with the next point version, for example
    `20261005.1`. You can stage the branches in any order.
5.  For each release, do [A4](#a4-verify-the-publish). Only the highest version
    gets `latest` and the "Latest" label.
6.  Publish the security advisory.

Releases made before this process (for example `release-20260928.0`) do not have
a branch. Create the branch one time from the tag. Then add the release
workflow files to the branch, or use [Playbook B](#playbook-b-command-line):

```bash
git push origin 'release-20260928.0^{commit}:refs/heads/release/20260928'
```

### Troubleshooting

Symptom                                                    | Cause                                                       | Action
---------------------------------------------------------- | ----------------------------------------------------------- | ------
Cut: `release-X is not older than <date>`                  | This date has a release, or a newer release exists          | Wait for the next week. To fix the existing release, use [Playbook C](#playbook-c-security-backport).
"Workflow does not exist or does not have a workflow_dispatch trigger in this branch" | The selected branch does not contain the workflow | Use a branch that was cut from master after the workflows were added.
Stage: `already released as ...`                           | There is no new commit since the last release               | Merge the cherry-pick pull request first.
No Buildkite build after stage                             | The webhook did not start a build for the tag               | Examine the Buildkite webhook. As a fallback, do [B3](#b3-stage).
The Buildkite build failed                                 | A build or upload error                                     | Fix the problem. Then stage again with the same version. This replaces the staging tag.
Release Mirror failed                                      | The artifacts were late, or a network error occurred        | Run **Release Mirror** again with the tag.

### Do not

-   Delete or move a published `release-*` tag.
-   Use `gh release delete --cleanup-tag`.
-   Run a release workflow or open a public pull request for an embargoed fix
    before the embargo date.
-   Backport a fix that is not a security fix.
-   Use a second release process at the same time as this one.
