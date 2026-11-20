#!/usr/bin/env python3

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Prints the failed jobs and the job logs of gVisor Buildkite builds.

The failed command prints JSON. The log command prints plain text.

The main gVisor pipelines are public, so no Buildkite token is necessary.

BUILD is one of:
  - a build URL (any page of the build, including job links);
  - a GitHub pull request URL, which selects the newest build on the branch of
    the pull request;
  - a build number;
  - a branch name, which selects the newest build on that branch.
"""

import argparse
import concurrent.futures
import dataclasses
import html
import http.client
import json
import os
import re
import sys
import time
from typing import Any, Optional
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = "https://buildkite.com"
GITHUB_API_URL = "https://api.github.com"
DEFAULT_PIPELINE = "gvisor/pipeline"

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

# Matches both the /ORG/PIPELINE/builds/N and the
# /organizations/ORG/pipelines/PIPELINE/builds/N forms of build URLs.
_BUILD_URL_RE = re.compile(
    r"buildkite\.com/(?:organizations/)?([\w.-]+)/(?:pipelines/)?([\w.-]+)"
    r"/builds/(\d+)"
)

_PULL_URL_RE = re.compile(r"github\.com/([\w.-]+)/([\w.-]+)/pull/(\d+)")

# The CI hooks upload test logs to this bucket, as BUILD_ID/JOB_ID/PATH.
_ARTIFACT_URL_RE = re.compile(
    rf"https://storage\.googleapis\.com/gvisor-buildkite/{_UUID}/({_UUID})/"
)

# Matches the job ID in the part of a job URL after /builds/N.
_JOB_IN_URL_RE = re.compile(rf"(?:[?&]jid=|#|/jobs/)({_UUID})")

# Matches terminal control strings (APC, which has the Buildkite timestamps,
# DCS, SOS, PM and OSC), CSI sequences, and other escape sequences.
_ESCAPE_RE = re.compile(
    r"\x1b[_PX^\]][^\x07\x1b\r]*(?:\x07|\x1b\\)?"
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"
    r"|\x1b[ -/]*[0-~]"
)

# Matches the control characters other than tab and newline.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# Matches the lines in a job log that tell why a job failed. Bazel prints the
# test.log of each failed test in the job log.
_FAILURE_LINE_RE = re.compile(
    # Bazel test results, errors and summary lines.
    r"(?:FAIL|TIMEOUT|FLAKY|NO STATUS): //"
    r"|ERROR: "
    r"|//\S+\s.*\b(?:FAILED|TIMEOUT|NO STATUS|INCOMPLETE)\b"
    # make, git, Go panics, and Go and C++ compiler errors.
    r"|make: \*\*\*"
    r"|fatal: "
    r"|panic: "
    r"|[\w./-]+\.go:\d+:\d+: "
    r"|\S+:\d+:\d+: error: "
    # Google Test: failed tests and failed assertions.
    r"|\[  FAILED  \] [A-Za-z_]"
    r"|\S+:\d+: Failure$"
)

# Match the Go test lines that tell which test prints the next lines, the
# result of a test, and a message of a test.
_GO_TEST_RE = re.compile(r"=== (?:RUN|CONT|NAME|PAUSE)\s+(\S+)")
_GO_RESULT_RE = re.compile(r"( *)--- (FAIL|PASS|SKIP): (\S+)")
_GO_MESSAGE_RE = re.compile(r"( +)[\w./-]+\.go:\d+: ")

# Matches the Bazel summary line of a test target, e.g.
# "//foo:bar_test  FLAKY, failed in 1 out of 2 in 3.4s".
_TARGET_STATUS_RE = re.compile(
    r"(//\S+)\s+(?:\(cached\) )?"
    r"(PASSED|FAILED|FLAKY|TIMEOUT|NO STATUS|INCOMPLETE)\b"
)

# Matches Bazel progress lines, e.g. "[4,936 / 4,941] Testing //foo:bar".
_PROGRESS_RE = re.compile(r"^\[[\d,]+ / [\d,]+\] ")

# Matches the local test.log path in Bazel test results.
_LOCAL_TEST_LOG_RE = re.compile(r" \(see /\S+\)$")

# Buildkite prints this line when a job step fails.
_ERROR_MARKER = "\U0001f6a8 Error"

_FETCH_ATTEMPTS = 3
_MAX_PAGES = 100
_MAX_FAILURE_LINES = 60
# The number of lines after a Google Test assertion failure, which has the
# expected and actual values.
_ASSERTION_LINES = 4
_MAX_LINE_LENGTH = 500


class Error(Exception):
  """A user-facing error."""


@dataclasses.dataclass(frozen=True)
class Build:
  """Identifies a Buildkite build."""

  org: str
  pipeline: str
  number: int

  @property
  def url(self) -> str:
    return f"{BASE_URL}/{self.org}/{self.pipeline}/builds/{self.number}"

  def data_url(self, name: str) -> str:
    return f"{self.url}/data/{name}"

  def job_log_url(self, job_id: str) -> str:
    return (
        f"{BASE_URL}/organizations/{self.org}/pipelines/{self.pipeline}"
        f"/builds/{self.number}/jobs/{job_id}/download.txt"
    )


def _fetch(url: str) -> bytes:
  """Returns the body of url, and retries on server and network errors."""

  req = urllib.request.Request(
      url, headers={"User-Agent": "gvisor-tools-buildkite"}
  )
  for attempt in range(_FETCH_ATTEMPTS):
    last = attempt == _FETCH_ATTEMPTS - 1
    try:
      with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()
    except urllib.error.HTTPError as e:
      e.close()
      if (e.code < 500 and e.code != 429) or last:
        # Buildkite returns 406 for the JSON of builds that do not exist, and
        # 403 for private pipelines.
        hint = ""
        if e.code in (403, 404, 406):
          hint = " (not found, or not public)"
        raise Error(f"{url}: HTTP {e.code}{hint}") from e
    except (OSError, http.client.HTTPException) as e:
      if last:
        raise Error(f"{url}: {getattr(e, 'reason', None) or e}") from e
    time.sleep(2**attempt)
  raise AssertionError("unreachable")


def _fetch_json(url: str):
  body = _fetch(url)
  try:
    return json.loads(body)
  except ValueError as e:
    raise Error(f"{url}: bad JSON response: {e}") from e


def _fetch_records(url: str) -> list[dict[str, Any]]:
  """Returns all records of a paginated Buildkite data endpoint."""

  records, page_url = [], url
  for _ in range(_MAX_PAGES):
    page = _fetch_json(page_url)
    records.extend(page.get("records") or [])
    if not page.get("has_next_page") or not page.get("end_cursor"):
      return records
    sep = "&" if "?" in url else "?"
    page_url = f"{url}{sep}after={urllib.parse.quote(page['end_cursor'])}"
  print(f"warning: {url}: results are truncated", file=sys.stderr)
  return records


def _latest_build(org: str, pipeline: str, branch: str) -> int:
  """Returns the number of the newest build of pipeline on branch."""

  query = urllib.parse.urlencode({"branch": branch})
  page = _fetch(f"{BASE_URL}/{org}/{pipeline}/builds?{query}").decode()
  m = re.search(rf"/{re.escape(org)}/{re.escape(pipeline)}/builds/(\d+)", page)
  if not m:
    raise Error(f"no builds of {org}/{pipeline} on branch {branch!r}")
  return int(m.group(1))


def _pull_request_branch(owner: str, repo: str, number: int) -> str:
  """Returns the Buildkite branch name of a GitHub pull request.

  Buildkite names the branch of a pull request from a fork OWNER:BRANCH.

  Args:
    owner: Repository owner.
    repo: Repository name.
    number: Pull request number.

  Raises:
    Error: If the GitHub API request fails.
  """

  url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/pulls/{number}"
  try:
    head = _fetch_json(url)["head"]
  except Error as e:
    raise Error(f"{e}; GitHub allows 60 API requests per hour") from e
  if (head.get("repo") or {}).get("full_name") == f"{owner}/{repo}":
    return head["ref"]
  return head["label"]


def parse_ref(
    ref: str,
    pipeline: str,
    resolve_branch=_latest_build,
    resolve_pull_request=_pull_request_branch,
) -> Build:
  """Returns the Build that ref refers to.

  pipeline is PIPELINE or ORG/PIPELINE. It applies to all refs except build
  URLs.

  Args:
    ref: Build URL, GitHub PR URL, build number, or branch name.
    pipeline: Pipeline name as PIPELINE or ORG/PIPELINE.
    resolve_branch: Callable resolving (org, pipeline, branch) to a build
      number.
    resolve_pull_request: Callable resolving (owner, repo, number) to a branch
      name.

  Raises:
    Error: If ref is an unsupported URL or pipeline is invalid.
  """

  m = _BUILD_URL_RE.search(ref)
  if m:
    return Build(m.group(1), m.group(2), int(m.group(3)))
  pull = _PULL_URL_RE.search(ref)
  if "://" in ref and not pull:
    raise Error(f"{ref}: not a Buildkite build or GitHub pull request URL")
  org, sep, name = pipeline.rpartition("/")
  if not sep:
    org = "gvisor"
  if not org or not name or "/" in org:
    raise Error(f"--pipeline {pipeline!r}: want PIPELINE or ORG/PIPELINE")
  if pull:
    owner, repo, number = pull.group(1), pull.group(2), int(pull.group(3))
    branch = resolve_pull_request(owner, repo, number)
    return Build(org, name, resolve_branch(org, name, branch))
  if ref.isascii() and ref.isdigit():
    return Build(org, name, int(ref))
  return Build(org, name, resolve_branch(org, name, ref))


def parse_job_url(url: str):
  """Returns the Build and the job ID of a job URL."""

  m = _BUILD_URL_RE.search(url)
  job = _JOB_IN_URL_RE.search(url, m.end()) if m else None
  if not job:
    raise Error(f"{url}: not a Buildkite job URL")
  return Build(m.group(1), m.group(2), int(m.group(3))), job.group(1)


def _compact(d: dict[str, Any]) -> dict[str, Any]:
  """Returns d without the keys whose values are None or empty."""

  return {
      k: v
      for k, v in d.items()
      if v is not None and (not isinstance(v, list) or v)
  }


def outcome(job: dict[str, Any]) -> str:
  """Returns the outcome of a job attempt.

  The outcome is passed, failed, soft_failed, canceled, skipped, or pending if
  the attempt did not finish yet.

  Args:
    job: Buildkite job record dictionary.
  """

  state = job.get("state")
  if state in ("canceling", "canceled"):
    return "canceled"
  if state in ("broken", "skipped"):
    return "skipped"
  if state not in ("finished", "timed_out", "expired"):
    return "pending"
  if job.get("passed"):
    return "passed"
  return "soft_failed" if job.get("soft_failed") else "failed"


def clean_log(raw: bytes) -> list[str]:
  """Returns the lines of a raw job log, without terminal control codes."""

  lines = raw.decode("utf-8", "replace").split("\n")
  if not lines[-1]:
    lines.pop()
  for i, line in enumerate(lines):
    line = _ESCAPE_RE.sub("", line)
    # Keep only the text after the last carriage return, as a terminal shows.
    line = line.rstrip("\r").rsplit("\r", 1)[-1]
    lines[i] = _CONTROL_CHAR_RE.sub("", line)
  return lines


def analyze_log(lines: list[str], excerpt_lines: int) -> dict[str, Any]:
  """Returns the lines of a job log that tell why the job failed.

  The command output ends at the first Buildkite error line. Hooks that run
  after the command, such as the artifact upload, print the rest of the log.
  Each failure line is kept once. If there are too many, the first and the
  last lines are kept.

  The messages of a Go test are kept only if the test fails. Without -v, Go
  prints the messages of a failed test after its "--- FAIL" line, indented
  more. With -v, Go prints the messages when the test prints them, after a
  "=== RUN", "=== CONT" or "=== NAME" line with the name of the test.

  Args:
    lines: Cleaned log lines.
    excerpt_lines: Maximum number of trailing command output lines to include.
  """

  end = next(
      (i for i, l in enumerate(lines) if l.startswith(_ERROR_MARKER)),
      len(lines),
  )
  failure_lines, seen = [], set()

  def add(line: str, once=True) -> None:
    if once:
      if line in seen:
        return
      seen.add(line)
    failure_lines.append(line)

  # The number of lines after an assertion failure that are still to add.
  context = 0
  # The Go test that prints the next lines, the messages of the Go tests that
  # did not end yet, and the indentation of the "--- FAIL" line that the next
  # messages belong to.
  go_test, go_messages, fail_indent = None, {}, None
  for line in lines[:end]:
    line = _LOCAL_TEST_LOG_RE.sub("", line[:_MAX_LINE_LENGTH])
    indent = len(line) - len(line.lstrip())
    if fail_indent is not None and line.strip() and indent <= fail_indent:
      fail_indent = None
    if m := _GO_TEST_RE.match(line):
      go_test, context = m.group(1), 0
    elif m := _GO_RESULT_RE.match(line):
      messages, context = go_messages.pop(m.group(3), []), 0
      if m.group(2) == "FAIL":
        add(line)
        for message in messages:
          add(message)
        fail_indent = len(m.group(1))
    elif m := _GO_MESSAGE_RE.match(line):
      context = 0
      if fail_indent is not None:
        add(line)
      elif go_test:
        go_messages.setdefault(go_test, []).append(line)
    elif _FAILURE_LINE_RE.match(line):
      context = _ASSERTION_LINES if line.endswith(": Failure") else 0
      add(line)
    elif context and line.strip():
      context -= 1
      add(line, once=False)
  omitted = len(failure_lines) - _MAX_FAILURE_LINES
  if omitted > 0:
    half = _MAX_FAILURE_LINES // 2
    failure_lines = failure_lines[:half] + failure_lines[-half:]
  body = [
      l
      for l in lines[:end]
      if l.strip() and l != "^^^ +++" and not _PROGRESS_RE.match(l)
  ]
  excerpt = body[-excerpt_lines:] if excerpt_lines > 0 else []
  return _compact({
      "error": lines[end] if end < len(lines) else None,
      "failure_lines": failure_lines,
      "omitted_failure_lines": max(omitted, 0) or None,
      "excerpt": [l[:_MAX_LINE_LENGTH] for l in excerpt],
  })


def target_statuses(lines: list[str]) -> dict[str, str]:
  """Returns the Bazel status of each test target in the summary of a log."""

  return {
      m.group(1): m.group(2)
      for line in lines
      if (m := _TARGET_STATUS_RE.match(line))
  }


def parse_failures_annotation(body: str):
  """Returns the targets in a "failures" annotation.

  Returns the targets by job ID, and the names of the targets that have no
  job ID.

  The CI post-command hook adds an entry for each target that failed, timed
  out or was flaky, which means that it passed when Bazel ran it again. The
  entry does not tell which of these. The entry links to the test.log
  artifact of the target, and the artifact URL contains the job ID. After the
  first 9 targets of a job, the entries have no link. The hook can add the
  same entry more than once.

  Args:
    body: HTML body of the "failures" annotation.
  """

  targets, unattributed = {}, []
  for href, target in re.findall(r'<a href="([^"]+)">([^<]+)</a>', body):
    href = html.unescape(href)
    target = html.unescape(target).strip()
    m = _ARTIFACT_URL_RE.match(href)
    if not m:
      unattributed.append(target)
      continue
    entry = {"target": target, "test_log_url": href}
    job_targets = targets.setdefault(m.group(1), [])
    if entry not in job_targets:
      job_targets.append(entry)
  for target in re.findall(r"<li>\s*(//[^<\s]+) \(no upload\)", body):
    unattributed.append(html.unescape(target))
  return targets, list(dict.fromkeys(unattributed))


def _annotated_targets(build: Build):
  """Returns the targets of build, as parse_failures_annotation does."""

  targets, unattributed = {}, []
  for a in _fetch_records(build.data_url("annotations")):
    if a.get("context") == "failures":
      by_job, without_job = parse_failures_annotation(
          (a.get("body") or {}).get("html") or ""
      )
      for job_id, t in by_job.items():
        targets.setdefault(job_id, []).extend(t)
      unattributed.extend(without_job)
  return targets, unattributed


def _build_info(b: dict[str, Any]) -> dict[str, Any]:
  return _compact({
      "number": b["number"],
      "url": f"{BASE_URL}{b['path']}",
      "state": b["state"],
      "branch": b.get("branch_name"),
      "commit": b.get("commit_id"),
      "message": (b.get("message") or "").split("\n", 1)[0],
      "pull_request": (b.get("pull_request") or {}).get("url"),
  })


def job_info(
    build: Build,
    job: dict[str, Any],
    targets: list[dict[str, Any]],
    retry: Optional[str],
) -> dict[str, Any]:
  """Returns the interesting fields of a job record.

  Args:
    build: Target Buildkite build.
    job: Job record dictionary from Buildkite.
    targets: Annotated targets associated with this job.
    retry: Outcome of the next attempt, or None if there is none.
  """

  return _compact({
      "name": job.get("name") or (job.get("step") or {}).get("label"),
      "parallel_job": job.get("parallel_group_index"),
      "state": job.get("state"),
      "exit_status": job.get("exit_status"),
      "attempt": (job.get("retries_count") or 0) + 1,
      "retry": retry,
      "soft_failed": job.get("soft_failed") or None,
      "url": f"{build.url}#{job['id']}",
      "annotated_targets": targets,
  })


def _matches(regex, info: dict[str, Any]) -> bool:
  fields = [info.get("name") or ""]
  fields += [t["target"] for t in info.get("annotated_targets", [])]
  return any(regex.search(f) for f in fields)


def _add_log(
    build: Build, job: dict[str, Any], info: dict[str, Any], excerpt_lines: int
) -> None:
  """Downloads and analyzes a job's log and updates info in place."""

  try:
    raw = _fetch(build.job_log_url(job["id"]))
  except Error as e:
    info["log_error"] = str(e)
    return
  lines = clean_log(raw)
  info["log"] = analyze_log(lines, excerpt_lines)
  statuses = target_statuses(lines)
  for t in info.get("annotated_targets", []):
    if t["target"] in statuses:
      t["status"] = statuses[t["target"]]


def failed(
    build: Build,
    regex=None,
    soft_failed=False,
    logs=False,
    all_attempts=False,
    excerpt_lines=20,
) -> dict[str, Any]:
  """Returns the failed jobs of build, sorted by job and attempt.

  If logs is set, adds the analysis of the job log of each attempt whose
  retry did not finish, or of all attempts if all_attempts is set.

  Args:
    build: Target Buildkite build.
    regex: Optional compiled regex filtering jobs by name or target.
    soft_failed: Whether to include soft-failed jobs.
    logs: Whether to download and analyze logs for failed attempts.
    all_attempts: With logs, also download logs whose retry finished.
    excerpt_lines: Number of trailing command output lines in each log excerpt.
  """

  b = _fetch_json(f"{build.url}.json")
  # The jobs endpoint returns all jobs of the build, of all attempts.
  jobs = {j["id"]: j for j in _fetch_records(build.data_url("jobs"))}
  listed = ("failed", "soft_failed") if soft_failed else ("failed",)
  targets, unattributed = _annotated_targets(build)
  entries = []
  for j in jobs.values():
    if outcome(j) not in listed:
      continue
    retry = j.get("retried_in_job_uuid")
    if retry:
      # A retry that is not in the list yet did not start.
      retry = outcome(jobs[retry]) if retry in jobs else "pending"
    entries.append((j, job_info(build, j, targets.get(j["id"], []), retry)))
  if regex:
    entries = [(j, i) for j, i in entries if _matches(regex, i)]
  entries.sort(
      key=lambda e: (
          e[1].get("name") or "",
          e[1].get("parallel_job", -1),
          e[1]["attempt"],
      )
  )
  if logs:
    todo = [
        e
        for e in entries
        if all_attempts or e[1].get("retry") not in ("passed", "failed")
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
      list(pool.map(lambda e: _add_log(build, *e, excerpt_lines), todo))
  infos = [i for _, i in entries]
  result = {"build": _build_info(b), "jobs": infos}
  if unattributed:
    result["unattributed_targets"] = unattributed
  return result


def _regex(pattern: str):
  try:
    return re.compile(pattern, re.IGNORECASE)
  except re.error as e:
    raise argparse.ArgumentTypeError(f"bad regex {pattern!r}: {e}") from e


def _parse_args(argv):
  """Parses command-line arguments."""

  parser = argparse.ArgumentParser(
      description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  sub = parser.add_subparsers(dest="command", required=True)

  p = sub.add_parser(
      "failed",
      help="print the failed jobs of a build",
      description=(
          "Prints the failed jobs of a build. A job that Buildkite retried has"
          " an entry for each failed attempt, and retry is the outcome of the"
          " next attempt."
      ),
  )
  p.add_argument(
      "build", help="build URL, GitHub pull request URL, number or branch"
  )
  p.add_argument(
      "regex",
      nargs="?",
      type=_regex,
      help=(
          "only print the jobs whose name or annotated Bazel targets match"
          " this case-insensitive regular expression"
      ),
  )
  p.add_argument(
      "--pipeline",
      default=DEFAULT_PIPELINE,
      help=(
          "PIPELINE or ORG/PIPELINE for all builds except build URLs"
          " (default: %(default)s)"
      ),
  )
  p.add_argument(
      "--soft-failed",
      action="store_true",
      help="also print soft-failed jobs, which do not fail the build",
  )
  p.add_argument(
      "--logs",
      action="store_true",
      help=(
          "download the log of each failed attempt whose retry did not"
          " finish, and add the failure lines, the end of the command output,"
          " and the Bazel status of the annotated targets"
      ),
  )
  p.add_argument(
      "--all-attempts",
      action="store_true",
      help=(
          "with --logs, also download the logs of attempts whose retry finished"
      ),
  )
  p.add_argument(
      "--excerpt-lines",
      type=int,
      default=20,
      help=(
          "number of command output lines in the --logs excerpt (default:"
          " %(default)s)"
      ),
  )

  p = sub.add_parser("log", help="print the log of a job as plain text")
  p.add_argument("job", help="job URL")
  p.add_argument("--tail", type=int, help="print only the last TAIL lines")
  return parser.parse_args(argv)


def main(argv) -> int:
  args = _parse_args(argv)
  try:
    if args.command == "log":
      build, job_id = parse_job_url(args.job)
      lines = clean_log(_fetch(build.job_log_url(job_id)))
      if args.tail is not None:
        lines = lines[-args.tail :] if args.tail > 0 else []
      sys.stdout.write("".join(l + "\n" for l in lines))
      return 0
    result = failed(
        parse_ref(args.build, args.pipeline),
        regex=args.regex,
        soft_failed=args.soft_failed,
        logs=args.logs,
        all_attempts=args.all_attempts,
        excerpt_lines=args.excerpt_lines,
    )
  except Error as e:
    print(f"{sys.argv[0]}: error: {e}", file=sys.stderr)
    return 1
  json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
  sys.stdout.write("\n")
  return 0


if __name__ == "__main__":
  try:
    sys.exit(main(sys.argv[1:]))
  except BrokenPipeError:
    # The reader of stdout, such as head(1), exited early.
    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    sys.exit(1)
