#!/usr/bin/env python3

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Checks release staging and publication with fake build and registry commands."""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("release", sys.argv.pop(1))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
TAG = "release-20261027.2"
VERSION = "20261027.2.0"
IMAGE = "registry.example/project/installer"
CHART = "oci://registry.example/project/charts"
DIGESTS = {"amd64": "sha256:" + "a" * 64, "arm64": "sha256:" + "b" * 64}


def image_archive(path, architecture):
  with tarfile.open(path, "w") as archive:
    for name, value in {
        "manifest.json": [{"Config": "config.json"}],
        "config.json": {"architecture": architecture, "os": "linux"},
    }.items():
      content = json.dumps(value).encode()
      info = tarfile.TarInfo(name)
      info.size = len(content)
      archive.addfile(info, io.BytesIO(content))


class Commands:
  """Produces build artifacts and registry responses without external tools."""

  def __init__(self):
    self.calls = []
    self.stamp = TAG
    self.fail = None
    self.bad_platform = False
    self.bad_index = False

  def run(self, args, **kwargs):
    del kwargs
    self.calls.append(args)
    if self.fail and args[:len(self.fail)] == self.fail:
      raise subprocess.CalledProcessError(1, args)
    stdout = ""
    if args[:2] == ["git", "describe"]:
      stdout = self.stamp
    elif args[:2] == ["git", "rev-parse"]:
      stdout = "1234567890abcdef"
    elif args[:2] == ["make", "copy"]:
      directory = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("DESTINATION=")))
      architecture = "amd64" if any("--config=x86_64" in arg for arg in args) else "arm64"
      image_archive(directory / "image.tar", "amd64" if self.bad_platform else architecture)
    elif args[:2] == ["helm", "package"]:
      destination = Path(args[args.index("--destination") + 1])
      version = args[args.index("--version") + 1]
      (destination / f"gvisor-{version}.tgz").write_bytes(b"packaged chart")
    elif args[:2] == ["helm", "template"]:
      stdout = f"image: {IMAGE}:{TAG}\n"
    elif args[:2] == ["crane", "digest"]:
      stdout = next((digest for arch, digest in DIGESTS.items() if args[2].endswith("-" + arch)), "sha256:" + "c" * 64)
    elif args[:2] == ["crane", "manifest"]:
      stdout = json.dumps({"manifests": [
          {"platform": {"os": "linux", "architecture": arch}, "digest": digest}
          for arch, digest in DIGESTS.items()
          if not self.bad_index or arch == "amd64"
      ]})
    return subprocess.CompletedProcess(args, 0, stdout)


class ReleaseTest(unittest.TestCase):

  def setUp(self):
    self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR"))
    self.addCleanup(self.temp.cleanup)
    self.root = Path(self.temp.name)
    self.destination = self.root / "stage"
    self.commands = Commands()
    self.addCleanup(mock.patch.stopall)
    mock.patch.object(RELEASE, "ROOT", self.root).start()
    mock.patch.object(RELEASE.subprocess, "run", self.commands.run).start()
    mock.patch.object(RELEASE.shutil, "which", side_effect=lambda name: "/fake/" + name).start()
    mock.patch.dict(os.environ, {
        "GVISOR_INSTALLER_IMAGE_REPOSITORY": IMAGE,
        "GVISOR_HELM_REPOSITORY": CHART,
    }, clear=True).start()
    chart = self.root / RELEASE.CHART
    chart.mkdir(parents=True)
    (chart / "Chart.yaml").write_text("name: gvisor\nversion: 0.0.0\nappVersion: dev\n")
    (chart / "values.yaml").write_text('image:\n  repository: ""\n  tag: ""\n')

  def test_version_mapping(self):
    for tag, version in {
        "release-20261027": "20261027.0.0",
        "release-20261027.0": "20261027.0.0",
        "release-20261027.12": "20261027.12.0",
        "release-20261027.4294967295": "20261027.4294967295.0",
    }.items():
      with self.subTest(tag=tag):
        self.assertEqual(RELEASE.chart_version(tag), version)

  def test_invalid_versions(self):
    for tag in ("dev", "release-20261027.0-dirty", "release-20261027.0-staging",
                "release-20260230.0", "release-20261027.0-1-gabcd", "20261027.0",
                "release-20261027.01", "release-20261027.00", "release-20261027.+1",
                "release-20261027.4294967296", "release-20261027." + "9" * 5000,
                "release-19991027.0", "release-21001027.0"):
      with self.subTest(tag=tag), self.assertRaises(ValueError):
        RELEASE.chart_version(tag)

  def test_stage_does_not_publish(self):
    RELEASE.stage(TAG, self.destination)
    manifest = RELEASE.load_stage(self.destination)
    self.assertEqual(manifest["release"], TAG)
    self.assertEqual(manifest["chart_version"], VERSION)
    self.assertEqual(set(manifest["images"]), {"amd64", "arm64"})
    self.assertEqual(len([args for args in self.commands.calls if args[:2] == ["make", "copy"]]), 2)
    self.assertFalse(any(args[0] == "crane" or args[:2] == ["helm", "push"] for args in self.commands.calls))
    chart = self.destination / "chart" / "gvisor"
    self.assertIn(f'version: "{VERSION}"', (chart / "Chart.yaml").read_text())
    self.assertIn(f'appVersion: "{TAG}"', (chart / "Chart.yaml").read_text())
    self.assertIn(f'repository: "{IMAGE}"', (chart / "values.yaml").read_text())
    self.assertIn(f'tag: "{TAG}"', (chart / "values.yaml").read_text())
    self.assertIn(f"{IMAGE}:{TAG}", (self.destination / "manifest.yaml").read_text())
    self.assertIn("version: 0.0.0", (self.root / RELEASE.CHART / "Chart.yaml").read_text())

  def test_requires_explicit_destinations(self):
    for image, chart in (("", CHART), (IMAGE, ""), (IMAGE + ":latest", CHART),
                         (IMAGE, "https://example.com/charts")):
      with self.subTest(image=image, chart=chart), self.assertRaises(ValueError):
        RELEASE.repositories(image, chart)
    os.environ.pop("GVISOR_INSTALLER_IMAGE_REPOSITORY")
    with self.assertRaises(ValueError):
      RELEASE.stage(TAG, self.destination)
    self.assertFalse(self.destination.exists())
    self.assertEqual(self.commands.calls, [])

  def test_requires_clean_exact_release_stamp(self):
    for stamp in (TAG + "-dirty", TAG + "-1-gabcdef", "dev"):
      self.commands.stamp = stamp
      with self.subTest(stamp=stamp), self.assertRaises(ValueError):
        RELEASE.stage(TAG, self.destination)
    self.assertFalse(self.destination.exists())

  def test_refuses_existing_destination(self):
    self.destination.mkdir()
    (self.destination / "keep").write_text("original")
    with self.assertRaises(FileExistsError):
      RELEASE.stage(TAG, self.destination)
    self.assertEqual((self.destination / "keep").read_text(), "original")

  def test_wrong_archive_platform_fails_stage(self):
    self.commands.bad_platform = True
    with self.assertRaisesRegex(ValueError, "linux/arm64"):
      RELEASE.stage(TAG, self.destination)
    self.assertFalse((self.destination / RELEASE.MANIFEST).exists())

  def test_publish_image_index_before_chart(self):
    RELEASE.stage(TAG, self.destination)
    self.commands.calls.clear()
    RELEASE.publish(self.destination)
    writes = [args for args in self.commands.calls if args[:2] in (
        ["crane", "push"], ["crane", "index"], ["helm", "push"])]
    self.assertEqual([args[:2] for args in writes], [
        ["crane", "push"], ["crane", "push"], ["crane", "index"], ["helm", "push"]])
    self.assertEqual(writes[0][-1], f"{IMAGE}:{TAG}-amd64")
    self.assertEqual(writes[1][-1], f"{IMAGE}:{TAG}-arm64")
    self.assertEqual(writes[2], ["crane", "index", "append", "--manifest",
                               f"{IMAGE}@{DIGESTS['amd64']}", "--manifest",
                               f"{IMAGE}@{DIGESTS['arm64']}", "--tag", f"{IMAGE}:{TAG}"])
    self.assertEqual(writes[-1][-1], CHART)

  def test_changed_stage_fails_before_publish(self):
    RELEASE.stage(TAG, self.destination)
    (self.destination / f"gvisor-{VERSION}.tgz").write_bytes(b"changed")
    self.commands.calls.clear()
    with self.assertRaisesRegex(ValueError, "checksum mismatch"):
      RELEASE.publish(self.destination)
    self.assertEqual(self.commands.calls, [])

  def test_index_failure_does_not_publish_chart(self):
    RELEASE.stage(TAG, self.destination)
    for bad_index in (False, True):
      self.commands.calls.clear()
      self.commands.fail = None if bad_index else ["crane", "index", "append"]
      self.commands.bad_index = bad_index
      with self.subTest(bad_index=bad_index), self.assertRaises((subprocess.CalledProcessError, ValueError)):
        RELEASE.publish(self.destination)
      self.assertFalse(any(args[:2] == ["helm", "push"] for args in self.commands.calls))

  def test_missing_helm_fails_before_any_image_push(self):
    RELEASE.stage(TAG, self.destination)
    self.commands.calls.clear()
    with mock.patch.object(RELEASE.shutil, "which", side_effect=lambda name: None if name == "helm" else "/fake/" + name):
      with self.assertRaisesRegex(ValueError, "helm"):
        RELEASE.publish(self.destination)
    self.assertEqual(self.commands.calls, [])

  def test_ci_requires_explicit_enablement_and_staging_tag(self):
    os.environ["BUILDKITE_TAG"] = TAG + "-staging"
    RELEASE.ci("ci-stage", self.destination)
    self.assertEqual(self.commands.calls, [])
    os.environ["GVISOR_KUBERNETES_RELEASE"] = "true"
    os.environ["BUILDKITE_TAG"] = ""
    RELEASE.ci("ci-stage", self.destination)
    self.assertEqual(self.commands.calls, [])
    os.environ["GVISOR_KUBERNETES_RELEASE"] = "typo"
    with self.assertRaises(ValueError):
      RELEASE.ci("ci-stage", self.destination)

  def test_ci_publishes_the_matching_staged_release(self):
    os.environ["GVISOR_KUBERNETES_RELEASE"] = "true"
    os.environ["BUILDKITE_TAG"] = TAG + "-staging"
    RELEASE.ci("ci-stage", self.destination)
    self.assertFalse(any(args[0] == "crane" for args in self.commands.calls))
    RELEASE.ci("ci-publish", self.destination)
    self.assertEqual(self.commands.calls[-1][:2], ["helm", "push"])

  def test_ci_rejects_mismatched_staged_release(self):
    RELEASE.stage(TAG, self.destination)
    self.commands.calls.clear()
    os.environ["GVISOR_KUBERNETES_RELEASE"] = "true"
    os.environ["BUILDKITE_TAG"] = "release-20261027.3-staging"
    with self.assertRaisesRegex(ValueError, "does not match"):
      RELEASE.ci("ci-publish", self.destination)
    self.assertEqual(self.commands.calls, [])


if __name__ == "__main__":
  unittest.main()
