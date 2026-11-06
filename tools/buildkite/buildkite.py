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

"""Prints the failed jobs of a gVisor Buildkite build as JSON.

The main gVisor pipelines are public, so no Buildkite token is necessary.

BUILD is one of:
  - a build URL (any page of the build, including job links);
  - a GitHub pull request URL, which selects the newest build on the branch of
    the pull request;
  - a build number;
  - a branch name, which selects the newest build on that branch.
"""

import argparse
import dataclasses
import html
import http.client
import json
import os
import re
import sys
import time
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

_FETCH_ATTEMPTS = 3
_MAX_PAGES = 100


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


def _fetch_records(url: str) -> list:
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


def _compact(d: dict) -> dict:
  """Returns d without the keys whose values are None or empty."""

  return {k: v for k, v in d.items() if v is not None and v != []}


def outcome(job: dict) -> str:
  """Returns the outcome of a job attempt.

  The outcome is passed, failed, soft_failed, canceled, skipped, or pending if
  the attempt did not finish yet.
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


def _build_info(b: dict) -> dict:
  return _compact({
      "number": b["number"],
      "url": f"{BASE_URL}{b['path']}",
      "state": b["state"],
      "branch": b.get("branch_name"),
      "commit": b.get("commit_id"),
      "message": (b.get("message") or "").split("\n", 1)[0],
      "pull_request": (b.get("pull_request") or {}).get("url"),
  })


def job_info(build: Build, job: dict, targets: list, retry) -> dict:
  """Returns the interesting fields of a job record.

  retry is the outcome of the next attempt, or None if there is none.
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


def _matches(regex, info: dict) -> bool:
  fields = [info.get("name") or ""]
  fields += [t["target"] for t in info.get("annotated_targets", [])]
  return any(regex.search(f) for f in fields)


def failed(build: Build, regex=None, soft_failed=False) -> dict:
  """Returns the failed jobs of build, sorted by job and attempt."""

  b = _fetch_json(f"{build.url}.json")
  # The jobs endpoint returns all jobs of the build, of all attempts.
  jobs = {j["id"]: j for j in _fetch_records(build.data_url("jobs"))}
  listed = ("failed", "soft_failed") if soft_failed else ("failed",)
  targets, unattributed = _annotated_targets(build)
  infos = []
  for j in jobs.values():
    if outcome(j) not in listed:
      continue
    retry = j.get("retried_in_job_uuid")
    if retry:
      # A retry that is not in the list yet did not start.
      retry = outcome(jobs[retry]) if retry in jobs else "pending"
    infos.append(job_info(build, j, targets.get(j["id"], []), retry))
  if regex:
    infos = [i for i in infos if _matches(regex, i)]
  infos.sort(
      key=lambda i: (
          i.get("name") or "",
          i.get("parallel_job", -1),
          i["attempt"],
      )
  )
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
  return parser.parse_args(argv)


def main(argv) -> int:
  args = _parse_args(argv)
  try:
    build = parse_ref(args.build, args.pipeline)
    result = failed(build, args.regex, args.soft_failed)
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
