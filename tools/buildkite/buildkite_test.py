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

"""Tests for buildkite.py. These tests do not use the network."""

import contextlib
import http.client
import io
import json
import os
import subprocess
import unittest
from unittest import mock
import urllib.error

import buildkite

_JOB = "01a1adda-c906-4b1a-9892-62c1f2adc405"
_BUILD_UUID = "01a1adcc-cbcd-433f-912a-558714751e1c"
_BUILD_URL = "https://buildkite.com/gvisor/pipeline/builds/1"
_BUILD = buildkite.Build("gvisor", "pipeline", 1)


def _no_branch(org, pipeline, branch):
  raise AssertionError(f"unexpected branch lookup: {org}/{pipeline} {branch}")


def _no_pull_request(owner, repo, number):
  raise AssertionError(f"unexpected lookup: {owner}/{repo}#{number}")


def _job_id(n: int) -> str:
  return f"00000000-0000-0000-0000-{n:012d}"


def _artifact_url(job_id: str, target: str) -> str:
  return (
      f"https://storage.googleapis.com/gvisor-buildkite/{_BUILD_UUID}/{job_id}"
      f"/home/agent/testlogs/{target}/test.log"
  )


class FakeFetch:
  """Replaces buildkite._fetch with fixed responses, by URL."""

  def __init__(self, responses: dict):
    self.responses = responses
    self.urls = []

  def __call__(self, url):
    self.urls.append(url)
    if url not in self.responses:
      raise buildkite.Error(f"{url}: not found")
    body = self.responses[url]
    if isinstance(body, Exception):
      raise body
    if isinstance(body, bytes):
      return body
    return json.dumps(body).encode()


def _job(n, name, retry=None, **fields):
  return {
      "id": _job_id(n),
      "type": "script",
      "name": name,
      "state": "finished",
      "passed": False,
      "exit_status": 2,
      "retried_in_job_uuid": _job_id(retry) if retry else None,
      **fields,
  }


def _build_responses() -> dict:
  """Returns the responses of a build with these jobs.

  - Container tests: attempt 1 and its retry, attempt 2, fail container_test.
    The hook adds the entry of attempt 2 twice.
  - Syscall tests: attempt 3 fails mmap_test, and its retry, job 4, passes.
  - Docker tests: attempt 5 fails, and its retry, job 6, is canceled.
  - Benchmarks: job 7 soft-fails.
  - Unit tests: attempt 8 fails, and its retry, job 9, runs.
  - Go tests: attempt 10 fails, and its retry, job 11, is not in the list.
  - Build: job 12 passes.
  """

  failures = (
      "<ul>\n"
      f'<li><a href="{_artifact_url(_job_id(1), "container")}">'
      "//runsc/container:container_test</a></li>\n"
      f'<li><a href="{_artifact_url(_job_id(2), "container")}">'
      "//runsc/container:container_test</a></li>\n"
      f'<li><a href="{_artifact_url(_job_id(2), "container")}">'
      "//runsc/container:container_test</a></li>\n"
      f'<li><a href="{_artifact_url(_job_id(3), "mmap")}">'
      "//test/syscalls:mmap_test</a></li>\n"
      "<li>//test/syscalls:many_test (no upload)</li>\n"
      "</ul>"
  )
  data = f"{_BUILD_URL}/data"
  return {
      f"{_BUILD_URL}.json": {
          "number": 1,
          "path": "/gvisor/pipeline/builds/1",
          "state": "failed",
          "branch_name": "master",
          "message": "Title\n\nBody",
      },
      f"{data}/jobs": {
          "records": [
              _job(12, "Build", passed=True, exit_status=0),
              _job(5, "Docker tests", retry=6, exit_status=None),
              _job(6, "Docker tests", state="canceled", retries_count=1),
              _job(2, "Container tests", retries_count=1),
              _job(3, "Syscall tests", retry=4, parallel_group_index=3),
              _job(
                  4,
                  "Syscall tests",
                  parallel_group_index=3,
                  retries_count=1,
                  passed=True,
                  exit_status=0,
              ),
              _job(1, "Container tests", retry=2),
              _job(7, "Benchmarks", soft_failed=True),
              _job(8, "Unit tests", retry=9),
              _job(9, "Unit tests", state="running", exit_status=None),
              _job(10, "Go tests", retry=11, exit_status=-1),
          ]
      },
      f"{data}/annotations": {
          "records": [
              {"context": "failures", "body": {"html": failures}},
              {"context": "profiles", "body": {"html": "<p>other</p>"}},
          ]
      },
  }


class ParseRefTest(unittest.TestCase):

  def parse(
      self,
      ref,
      pipeline="gvisor/pipeline",
      resolve=_no_branch,
      resolve_pull_request=_no_pull_request,
  ):
    return buildkite.parse_ref(ref, pipeline, resolve, resolve_pull_request)

  def test_number(self):
    self.assertEqual(
        self.parse("53678"), buildkite.Build("gvisor", "pipeline", 53678)
    )
    for pipeline in ["release", "gvisor/release"]:
      with self.subTest(pipeline=pipeline):
        self.assertEqual(
            self.parse("12", pipeline=pipeline),
            buildkite.Build("gvisor", "release", 12),
        )
    self.assertEqual(
        self.parse("12", pipeline="other/release"),
        buildkite.Build("other", "release", 12),
    )

  def test_build_urls(self):
    build = buildkite.Build("gvisor", "pipeline", 53678)
    for url in [
        "https://buildkite.com/gvisor/pipeline/builds/53678",
        f"https://buildkite.com/gvisor/pipeline/builds/53678#{_JOB}",
        "https://buildkite.com/organizations/gvisor/pipelines/pipeline"
        f"/builds/53678/jobs/{_JOB}/download.txt",
    ]:
      with self.subTest(url=url):
        # A build URL selects its own pipeline.
        self.assertEqual(self.parse(url, pipeline="release"), build)

  def test_branch(self):
    resolve = lambda org, pipeline, branch: {
        ("gvisor", "pipeline", "master"): 7,
        ("gvisor", "pipeline", "²"): 8,
    }[(org, pipeline, branch)]
    self.assertEqual(
        self.parse("master", resolve=resolve),
        buildkite.Build("gvisor", "pipeline", 7),
    )
    # "²" is a digit, but not a build number.
    self.assertEqual(
        self.parse("²", resolve=resolve),
        buildkite.Build("gvisor", "pipeline", 8),
    )

  def test_pull_request(self):
    resolve_pull_request = lambda owner, repo, number: {
        ("google", "gvisor", 17121): "test/cl1",
        # A branch name that looks like a build number.
        ("google", "gvisor", 7): "123",
    }[(owner, repo, number)]
    resolve = lambda org, pipeline, branch: {
        ("gvisor", "pipeline", "test/cl1"): 53747,
        ("gvisor", "release", "test/cl1"): 9,
        ("gvisor", "pipeline", "123"): 8,
    }[(org, pipeline, branch)]
    for url, pipeline, want in [
        ("https://github.com/google/gvisor/pull/17121", "pipeline", 53747),
        ("https://github.com/google/gvisor/pull/17121/files", "release", 9),
        ("github.com/google/gvisor/pull/17121#issue-1", "pipeline", 53747),
        ("https://github.com/google/gvisor/pull/7", "pipeline", 8),
    ]:
      with self.subTest(url=url, pipeline=pipeline):
        build = self.parse(url, pipeline, resolve, resolve_pull_request)
        self.assertEqual(build.number, want)

  def test_pull_request_branch(self):
    pulls = "https://api.github.com/repos/google/gvisor/pulls"
    fetch = FakeFetch({
        f"{pulls}/1": {
            "head": {
                "ref": "test/cl1",
                "label": "google:test/cl1",
                "repo": {"full_name": "google/gvisor"},
            }
        },
        f"{pulls}/2": {
            "head": {
                "ref": "fix",
                "label": "someone:fix",
                "repo": {"full_name": "someone/gvisor"},
            }
        },
        # The fork was deleted.
        f"{pulls}/3": {
            "head": {"ref": "fix", "label": "someone:fix", "repo": None}
        },
    })
    with mock.patch.object(buildkite, "_fetch", fetch):
      for number, want in [
          (1, "test/cl1"),
          (2, "someone:fix"),
          (3, "someone:fix"),
      ]:
        with self.subTest(number=number):
          self.assertEqual(
              buildkite._pull_request_branch("google", "gvisor", number), want
          )
      with self.assertRaisesRegex(buildkite.Error, "60 API requests"):
        buildkite._pull_request_branch("google", "gvisor", 4)

  def test_errors(self):
    with self.assertRaises(buildkite.Error):
      self.parse("https://github.com/google/gvisor/issues/1")
    for pipeline in ["", "gvisor/", "/pipeline", "a/b/c"]:
      with self.subTest(pipeline=pipeline):
        with self.assertRaises(buildkite.Error):
          self.parse("1", pipeline=pipeline)


class FetchTest(unittest.TestCase):

  def fetch(self, *results):
    results = list(results)

    def urlopen(req, timeout):
      result = results.pop(0)
      if isinstance(result, Exception):
        raise result
      return contextlib.nullcontext(mock.Mock(read=lambda: result))

    with mock.patch.object(buildkite.urllib.request, "urlopen", urlopen):
      with mock.patch.object(buildkite.time, "sleep"):
        return buildkite._fetch_json("https://x/y")

  @staticmethod
  def http_error(code):
    return urllib.error.HTTPError("https://x/y", code, "", {}, None)

  def test_retries(self):
    self.assertEqual(
        self.fetch(
            self.http_error(500),
            http.client.IncompleteRead(b"{"),
            b'{"a": 1}',
        ),
        {"a": 1},
    )
    with self.assertRaisesRegex(buildkite.Error, "timed out"):
      self.fetch(*[TimeoutError("timed out")] * 3)

  def test_errors(self):
    for code, want in [
        (406, "HTTP 406 \\(not found, or not public\\)"),
        (403, "HTTP 403 \\(not found, or not public\\)"),
        (400, "HTTP 400$"),
    ]:
      with self.subTest(code=code):
        with self.assertRaisesRegex(buildkite.Error, want):
          self.fetch(self.http_error(code))
    with self.assertRaisesRegex(buildkite.Error, "bad JSON"):
      self.fetch(b"<html>")

  def test_records(self):
    url = "https://x/data/jobs?state=failed"
    pages = FakeFetch({
        url: {"records": [1], "has_next_page": True, "end_cursor": "c1"},
        url + "&after=c1": {"records": [2], "has_next_page": False},
    })
    with mock.patch.object(buildkite, "_fetch", pages):
      self.assertEqual(buildkite._fetch_records(url), [1, 2])

    # A server that repeats the cursor must not cause an endless loop.
    loop = FakeFetch({
        url: {"records": [1], "has_next_page": True, "end_cursor": "c1"},
        url + "&after=c1": {
            "records": [2],
            "has_next_page": True,
            "end_cursor": "c1",
        },
    })
    stderr = io.StringIO()
    with mock.patch.object(buildkite, "_fetch", loop):
      with contextlib.redirect_stderr(stderr):
        records = buildkite._fetch_records(url)
    self.assertEqual(len(records), buildkite._MAX_PAGES)
    self.assertIn("truncated", stderr.getvalue())


class AnnotationTest(unittest.TestCase):

  def test_parse_failures_annotation(self):
    url = _artifact_url(_JOB, "runsc/container/container_test/shard_3_of_8")
    body = (
        f'<ul>\n<li>\n<a href="{url}">//runsc/container:container_test</a>'
        ' (<span class="ui-emoji">🧪</span> Container tests)\n'
        "<ul>\n<li>TestFromAnotherJob</li>\n</ul>\n</li>\n"
        f'<li><a href="{url}">//runsc/container:container_test</a></li>\n'
        "<li>//foo:many_test (no upload)</li>\n"
        '<li>\n<a href="https://example.com/no-ids">//foo:bar</a></li>\n'
        '<li><a href="file:///etc/passwd#/gvisor-buildkite/'
        f'{_BUILD_UUID}/{_JOB}/">//evil:target</a></li>\n'
        "<li>//foo:many_test (no upload)</li>\n"
        "</ul>"
    )
    self.assertEqual(
        buildkite.parse_failures_annotation(body),
        (
            {
                _JOB: [{
                    "target": "//runsc/container:container_test",
                    "test_log_url": url,
                }]
            },
            ["//foo:bar", "//evil:target", "//foo:many_test"],
        ),
    )


class OutcomeTest(unittest.TestCase):

  def test_outcome(self):
    for fields, want in [
        ({"state": "finished", "passed": True}, "passed"),
        ({"state": "finished", "passed": False}, "failed"),
        ({"state": "timed_out", "passed": False}, "failed"),
        ({"state": "finished", "soft_failed": True}, "soft_failed"),
        ({"state": "canceled"}, "canceled"),
        ({"state": "skipped"}, "skipped"),
        ({"state": "running"}, "pending"),
        ({"state": "scheduled"}, "pending"),
        ({}, "pending"),
    ]:
      with self.subTest(fields=fields):
        self.assertEqual(buildkite.outcome(fields), want)


class FailedTest(unittest.TestCase):

  def failed(self, responses=None, **kwargs):
    fetch = FakeFetch(responses or _build_responses())
    with mock.patch.object(buildkite, "_fetch", fetch):
      return buildkite.failed(_BUILD, **kwargs)

  def test_failed(self):
    self.assertEqual(
        self.failed(),
        {
            "build": {
                "number": 1,
                "url": _BUILD_URL,
                "state": "failed",
                "branch": "master",
                "message": "Title",
            },
            "jobs": [
                {
                    "name": "Container tests",
                    "state": "finished",
                    "exit_status": 2,
                    "attempt": 1,
                    "retry": "failed",
                    "url": f"{_BUILD_URL}#{_job_id(1)}",
                    "annotated_targets": [{
                        "target": "//runsc/container:container_test",
                        "test_log_url": _artifact_url(_job_id(1), "container"),
                    }],
                },
                {
                    "name": "Container tests",
                    "state": "finished",
                    "exit_status": 2,
                    "attempt": 2,
                    "url": f"{_BUILD_URL}#{_job_id(2)}",
                    "annotated_targets": [{
                        "target": "//runsc/container:container_test",
                        "test_log_url": _artifact_url(_job_id(2), "container"),
                    }],
                },
                {
                    "name": "Docker tests",
                    "state": "finished",
                    "attempt": 1,
                    "retry": "canceled",
                    "url": f"{_BUILD_URL}#{_job_id(5)}",
                },
                {
                    "name": "Go tests",
                    "state": "finished",
                    "exit_status": -1,
                    "attempt": 1,
                    "retry": "pending",
                    "url": f"{_BUILD_URL}#{_job_id(10)}",
                },
                {
                    "name": "Syscall tests",
                    "parallel_job": 3,
                    "state": "finished",
                    "exit_status": 2,
                    "attempt": 1,
                    "retry": "passed",
                    "url": f"{_BUILD_URL}#{_job_id(3)}",
                    "annotated_targets": [{
                        "target": "//test/syscalls:mmap_test",
                        "test_log_url": _artifact_url(_job_id(3), "mmap"),
                    }],
                },
                {
                    "name": "Unit tests",
                    "state": "finished",
                    "exit_status": 2,
                    "attempt": 1,
                    "retry": "pending",
                    "url": f"{_BUILD_URL}#{_job_id(8)}",
                },
            ],
            "unattributed_targets": ["//test/syscalls:many_test"],
        },
    )

  def test_filters(self):
    names = lambda result: [j["name"] for j in result["jobs"]]
    for pattern, want in [
        ("DOCKER", ["Docker tests"]),
        (":mmap_test$", ["Syscall tests"]),
        ("none", []),
    ]:
      with self.subTest(pattern=pattern):
        result = self.failed(regex=buildkite._regex(pattern))
        self.assertEqual(names(result), want)
    self.assertIn("Benchmarks", names(self.failed(soft_failed=True)))


class MainTest(unittest.TestCase):

  def test_main(self):
    stdout, stderr = io.StringIO(), io.StringIO()
    with mock.patch.object(buildkite, "_fetch", FakeFetch(_build_responses())):
      with contextlib.redirect_stdout(stdout):
        self.assertEqual(buildkite.main(["failed", "1", "syscall"]), 0)
      with contextlib.redirect_stderr(stderr):
        self.assertEqual(buildkite.main(["failed", "2"]), 1)
    self.assertEqual(len(json.loads(stdout.getvalue())["jobs"]), 1)
    self.assertIn("not found", stderr.getvalue())


class CommandTest(unittest.TestCase):

  def test_help(self):
    # Runs the command as AGENTS.md documents it, from the repository root.
    root = os.path.abspath(__file__)
    for _ in range(3):
      root = os.path.dirname(root)
    for args in [["--help"], ["failed", "--help"]]:
      with self.subTest(args=args):
        result = subprocess.run(
            ["tools/buildkite/buildkite.py", *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout)


if __name__ == "__main__":
  unittest.main()
