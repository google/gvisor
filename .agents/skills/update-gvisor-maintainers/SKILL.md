---
name: update-gvisor-maintainers
description: >
  Update the gVisor maintainer roster in governance/maintainers.yaml and regenerate
  the files derived from it (.github/reviewer.json and MAINTAINERS.md).
  Use when a maintainer goes on hiatus, returns from hiatus, is added, steps down to
  emeritus, changes employer, or when MAINTAINERS.md / reviewer.json are out of sync.
---

# Update the gVisor maintainer roster

`governance/maintainers.yaml` is the single source of truth.
`.github/reviewer.json` and `MAINTAINERS.md` are generated from it by
`//governance/tools/maintainers:maintainers_gen`, and `maintainers_test`
byte-compares both against the checked-in copies. So: edit the YAML, regenerate,
run the test. Never hand-edit the two generated files; the test will catch you,
and rightly so.

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
make run TARGETS=//governance/tools/maintainers:maintainers_gen \
  ARGS="-input governance/maintainers.yaml -format reviewer.json -output .github/reviewer.json"

make run TARGETS=//governance/tools/maintainers:maintainers_gen \
  ARGS="-input governance/maintainers.yaml -format MAINTAINERS.md -output MAINTAINERS.md"
```

`-format` takes the name of the file being generated, `reviewer.json` or
`MAINTAINERS.md`. Leave off `-output` to dump to stdout instead, which is handy
for eyeballing a change before writing it.

Then:

```bash
make test TARGETS=//governance/tools/maintainers/...
```

This fails if the YAML changed and you forgot to regenerate, or if someone
edited a generated file by hand.

## Before handing back

Show the user the diff across all three files (`governance/maintainers.yaml`,
`.github/reviewer.json`, `MAINTAINERS.md`) and let them confirm the roster reads
the way they meant it to.

If a generated file contains something the generator does not emit, that content
is drift, and regenerating is what removes it. Do not teach the generator to
reproduce it without asking first: the generator decides what those files
contain, not whatever happened to be committed.
