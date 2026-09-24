---
name: update-gvisor-maintainers
description: >
  Update the gVisor maintainer roster in governance/maintainers.yaml or the
  specialization areas in governance/areas.yaml, and regenerate the files derived
  from them (.github/reviewer.json, MAINTAINERS.md and CODEOWNERS).
  Use when a maintainer goes on hiatus, returns from hiatus, is added, steps down to
  emeritus, changes employer or specialization, or when MAINTAINERS.md /
  reviewer.json / CODEOWNERS are out of sync.
---

# Update the gVisor maintainer roster

`governance/maintainers.yaml` (the roster) and `governance/areas.yaml`
(specialization areas, each mapping a name to repository paths) are the single
source of truth. `.github/reviewer.json`, `MAINTAINERS.md` and `CODEOWNERS` are
generated from them by `//governance/tools/maintainers:maintainers_gen`, and the
`make governance-check` CI step byte-compares all three against the checked-in
copies. So: edit the YAML, regenerate, run the check. Never hand-edit the
generated files; the check will catch you, and rightly so.

## Schema

Each entry under `maintainers:`:

```yaml
  - name: Gee Vaïzaur           # Full name or nickname.
    github: gvaizaur            # GitHub username.
    affiliation: Independent    # Current employer, or "Independent".
    past_affiliation:           # Optional.
      - affiliation: Arasaka Corporation
        until: 2025-03-01
    started: 2018-05-08         # First contribution. The list is sorted by this.
    status: HIATUS_SINCE:2026-07-17
    areas: [gpu, networking]    # Optional. Sorted area names from areas.yaml;
                                # grants CODEOWNERS ownership of the paths of
                                # areas with enforced_review. Not for emeritus.
```

Each entry under `areas:` in `areas.yaml`:

```yaml
  - name: gpu                   # Sorted by name.
    enforced_review: false      # Required. `true` generates a CODEOWNERS
                                # section for the area, making
                                # specialized-maintainer review mandatory.
                                # Needs at least one non-emeritus maintainer
                                # with the area.
    paths:                      # Repo-root-relative dirs (/like/this), no
      - /images/gpu             # trailing slash. Each path in one area only.
```

`status` is one of three, and it drives everything downstream:

Status                      | Reviews | Merge permissions | `reviewer.json` | `MAINTAINERS.md`
--------------------------- | ------- | ----------------- | --------------- | ----------------
`ACTIVE`                    | yes     | yes               | `true`          | main table
`HIATUS_SINCE:YYYY-MM-DD`   | no      | yes               | `false`         | main table
`EMERITUS_SINCE:YYYY-MM-DD` | no      | no                | omitted         | emeritus table

`true` in `reviewer.json` means the GitHub workflow may auto-assign reviews to
them. `false` means they are still a maintainer, just not on the receiving end
of the assignment lottery. Hiatus is about reviews only, not permissions; that
is why hiatus maintainers still show up in the main `MAINTAINERS.md` table
alongside active ones.

## Common changes

Most of these are a one-line `status:` edit on an existing entry:

-   Goes on hiatus: `status: HIATUS_SINCE:<today>`.
-   Comes back from hiatus: `status: ACTIVE`. Drop the date; `ACTIVE` never
    carries one.
-   Steps down, or hits 12 months of inactivity: `status:
    EMERITUS_SINCE:<date>`.
-   Comes back from emeritus: `status: ACTIVE`, but only through the normal
    nomination process. See "Becoming a maintainer" in `GOVERNANCE.md`.

The two that are not:

-   New maintainer: insert the entry in `started` order, not at the end of the
    file.
-   Changed employer: update `affiliation`, and move the old one to
    `past_affiliation` with the date it ended as `until`.

Dates are real calendar dates, so go look up today's date rather than guessing
at one. If the user gave you a date, use theirs.

After any change, regenerate.

## Regenerate

```bash
make governance-regen
```

This regenerates all three files in place.

Then:

```bash
make governance-check
```

This fails if the YAML changed and you forgot to regenerate, or if someone
edited a generated file by hand.

## Before handing back

Show the user the diff across all changed files (`governance/maintainers.yaml`,
`governance/areas.yaml`, `.github/reviewer.json`, `MAINTAINERS.md`,
`CODEOWNERS`) and let them confirm the roster reads the way they meant it to.

If a generated file contains something the generator does not emit, that content
is drift, and regenerating is what removes it. Do not teach the generator to
reproduce it without asking first: the generator decides what those files
contain, not whatever happened to be committed.
