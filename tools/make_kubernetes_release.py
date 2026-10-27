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

"""Stages and publishes the Kubernetes installer for a tagged gVisor release."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parent.parent
CHART = Path("tools/gvisor_k8s_tool/helm/gvisor")
ARCHITECTURES = {"amd64": "x86_64", "arm64": "aarch64"}
IMAGE_TARGET = "//images/gvisor-installer:gvisor_installer_archive"
MANIFEST = "release.json"


def chart_version(release):
    """Converts release-YYYYMMDD[.PATCH] to the chart's SemVer version."""
    match = re.fullmatch(r"release-(20[0-9]{6})(?:\.(0|[1-9][0-9]*))?", release)
    if not match:
        raise ValueError("expected release-YYYYMMDD[.PATCH], got " + release)
    datetime.datetime.strptime(match[1], "%Y%m%d")
    patch = match[2] or "0"
    if len(patch) > 10 or int(patch) > 0xffffffff:
        raise ValueError("release revision must fit in uint32: " + release)
    return f"{match[1]}.{patch}.0"


def repositories(image, chart):
    """Validates explicit image and OCI chart destinations."""
    repository = r"[a-z0-9][a-z0-9.:-]*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
    if not re.fullmatch(repository, image):
        raise ValueError(
            "set GVISOR_INSTALLER_IMAGE_REPOSITORY to a registry/repository "
            "without a scheme, tag or digest"
        )
    chart = chart.removesuffix("/")
    if not chart.startswith("oci://") or not re.fullmatch(repository, chart[6:]):
        raise ValueError(
            "set GVISOR_HELM_REPOSITORY to oci://registry/namespace "
            "without the chart name or version"
        )
    return image, chart


def run(*args):
    """Runs a command from the source checkout and returns its stdout."""
    args = [str(arg) for arg in args]
    print("+ " + shlex.join(args), file=sys.stderr)
    try:
        return subprocess.run(
            args, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        if error.stdout:
            print(error.stdout, file=sys.stderr)
        raise


def require_tools(*names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise ValueError("install the required release tools on PATH: " + ", ".join(missing))


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def set_scalar(path, key, value, indent=""):
    content, count = re.subn(
        r"^" + re.escape(indent + key) + r":.*$",
        lambda _: indent + key + ": " + json.dumps(value),
        path.read_text(),
        flags=re.MULTILINE,
    )
    if count != 1:
        raise ValueError(f"expected one {key} entry in {path}")
    path.write_text(content)


def validate_archive(path, architecture):
    """Checks the platform recorded in a single-image Docker-save archive."""
    with tarfile.open(path) as archive:
        manifests = json.load(archive.extractfile("manifest.json"))
        if len(manifests) != 1:
            raise ValueError(f"expected one image in {path}")
        config = json.load(archive.extractfile(manifests[0]["Config"]))
    if config.get("os") != "linux" or config.get("architecture") != architecture:
        raise ValueError(f"expected linux/{architecture} in {path}")


def stage(release, destination):
    """Builds and packages artifacts without publishing to a registry."""
    version = chart_version(release)
    image_repository, chart_repository = repositories(
        os.environ.get("GVISOR_INSTALLER_IMAGE_REPOSITORY", ""),
        os.environ.get("GVISOR_HELM_REPOSITORY", ""),
    )
    require_tools("git", "make", "helm")
    # The workspace status command uses these same git describe options.
    stamped_version = run(
        "git", "describe", "--always", "--tags", "--exclude",
        "release-*-staging", "--abbrev=12", "--dirty",
    )
    if stamped_version != release:
        raise ValueError(
            f"the checkout stamps {stamped_version}, expected {release}. "
            "Use a clean checkout at the release tag"
        )
    commit = run("git", "rev-parse", "HEAD")
    destination = destination.resolve()
    # A release must never overwrite a previous local build.
    destination.mkdir(parents=True, exist_ok=False)
    images = {}
    for architecture, configuration in ARCHITECTURES.items():
        image_dir = destination / architecture
        image_dir.mkdir()
        run(
            "make", "copy", f"TARGETS={IMAGE_TARGET}",
            f"DESTINATION={image_dir}",
            f"BAZEL_OPTIONS=--config={configuration} --compilation_mode=opt",
        )
        archives = list(image_dir.rglob("*.tar"))
        if len(archives) != 1:
            raise ValueError(f"expected one image archive in {image_dir}")
        validate_archive(archives[0], architecture)
        images[architecture] = str(archives[0].relative_to(destination))

    chart = destination / "chart" / "gvisor"
    shutil.copytree(ROOT / CHART, chart)
    set_scalar(chart / "Chart.yaml", "version", version)
    set_scalar(chart / "Chart.yaml", "appVersion", release)
    set_scalar(chart / "values.yaml", "repository", image_repository, "  ")
    set_scalar(chart / "values.yaml", "tag", release, "  ")
    run("helm", "lint", "--strict", chart)
    run(
        "helm", "package", chart, "--version", version,
        "--app-version", release, "--destination", destination,
    )
    package = f"gvisor-{version}.tgz"
    rendered = run("helm", "template", "gvisor", destination / package)
    (destination / "manifest.yaml").write_text(rendered + "\n")
    files = [*images.values(), package, "manifest.yaml"]
    write_json(destination / MANIFEST, {
        "release": release,
        "chart_version": version,
        "commit": commit,
        "image_repository": image_repository,
        "chart_repository": chart_repository,
        "images": images,
        "chart": package,
        "sha256": {name: checksum(destination / name) for name in files},
    })
    print(f"Staged {release} in {destination}. No artifacts were published.")


def load_stage(destination):
    """Loads a complete stage and verifies its artifact checksums."""
    manifest = json.loads((destination / MANIFEST).read_text())
    version = chart_version(manifest["release"])
    if manifest["chart_version"] != version:
        raise ValueError("staged chart version does not match the release")
    repositories(manifest["image_repository"], manifest["chart_repository"])
    if set(manifest["images"]) != set(ARCHITECTURES):
        raise ValueError("staged release must contain amd64 and arm64 images")
    if manifest["chart"] != f"gvisor-{version}.tgz":
        raise ValueError("staged chart filename does not match the release")
    files = [*manifest["images"].values(), manifest["chart"], "manifest.yaml"]
    for name in files:
        path = (destination / name).resolve()
        if not path.is_relative_to(destination):
            raise ValueError(f"staged artifact escapes its directory: {name}")
        if checksum(path) != manifest["sha256"].get(name):
            raise ValueError(f"staged artifact checksum mismatch: {name}")
    for architecture, name in manifest["images"].items():
        validate_archive(destination / name, architecture)
    return manifest


def image_digest(reference):
    digest = run("crane", "digest", reference)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError(f"unexpected image digest for {reference}: {digest}")
    return digest


def publish(destination):
    """Publishes the platform images and index before the corresponding chart."""
    destination = destination.resolve()
    manifest = load_stage(destination)
    require_tools("crane", "helm")
    repository = manifest["image_repository"]
    release = manifest["release"]
    digests = {}
    for architecture in ARCHITECTURES:
        reference = f"{repository}:{release}-{architecture}"
        run("crane", "push", destination / manifest["images"][architecture], reference)
        digests[architecture] = image_digest(reference)
    reference = f"{repository}:{release}"
    args = ["crane", "index", "append"]
    for digest in digests.values():
        args += ["--manifest", f"{repository}@{digest}"]
    run(*args, "--tag", reference)
    digest = image_digest(reference)
    index = json.loads(run("crane", "manifest", f"{repository}@{digest}"))
    expected = {("linux", arch, value) for arch, value in digests.items()}
    actual = {
        (entry.get("platform", {}).get("os"),
         entry.get("platform", {}).get("architecture"), entry.get("digest"))
        for entry in index.get("manifests", [])
    }
    if actual != expected or len(index.get("manifests", [])) != 2:
        raise ValueError("published index does not contain the staged amd64 and arm64 images")
    run("helm", "push", destination / manifest["chart"], manifest["chart_repository"])
    print(f"Published {reference}@{digest}")
    print(f"Published {manifest['chart_repository']}/gvisor:{manifest['chart_version']}")


def ci(command, destination):
    """Runs a release action only for explicitly enabled tagged builds."""
    enabled = os.environ.get("GVISOR_KUBERNETES_RELEASE", "false")
    if enabled not in ("true", "false"):
        raise ValueError("GVISOR_KUBERNETES_RELEASE must be true or false")
    if enabled != "true":
        print("Kubernetes installer publication is disabled. "
              "Set GVISOR_KUBERNETES_RELEASE=true and configure both repositories to enable it.")
        return
    tag = os.environ.get("BUILDKITE_TAG", "")
    if not tag.endswith("-staging"):
        print("Kubernetes installer publication requires a staged release tag. Skipping this build.")
        return
    release = tag.removesuffix("-staging")
    chart_version(release)
    if command == "ci-stage":
        stage(release, destination)
    else:
        manifest = load_stage(destination.resolve())
        if manifest["release"] != release:
            raise ValueError("staged installer does not match the CI release tag")
        publish(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    version_parser = commands.add_parser("version", help="print the chart version for a release")
    version_parser.add_argument("release")
    stage_parser = commands.add_parser("stage", help="build into a new directory without publishing")
    stage_parser.add_argument("release")
    stage_parser.add_argument("destination", type=Path)
    for command in ("publish", "ci-stage", "ci-publish"):
        command_parser = commands.add_parser(command)
        command_parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "version":
            print(chart_version(args.release))
        elif args.command == "stage":
            stage(args.release, args.destination)
        elif args.command == "publish":
            publish(args.destination)
        else:
            ci(args.command, args.destination)
    except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
