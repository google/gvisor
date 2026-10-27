#!/usr/bin/env python3
# Copyright 2026 The gVisor Authors.
# SPDX-License-Identifier: Apache-2.0
"""Render the installation chart and check its host mutation boundaries.

Run with Python 3, PyYAML and Helm available.
"""

import pathlib
import shutil
import subprocess
import tempfile
import unittest

import yaml

CHART = pathlib.Path(__file__).resolve().parent / "gvisor"


def render(values=None, release="test", chart=CHART):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as f:
        yaml.safe_dump(values or {}, f)
        f.flush()
        result = subprocess.run(
            ["helm", "template", release, str(chart), "--namespace", "test-system",
             "--set", "image.repository=example.invalid/gvisor", "-f", f.name],
            check=True, capture_output=True, text=True,
        )
    return {doc["kind"]: doc for doc in yaml.safe_load_all(result.stdout) if doc}


class ChartTest(unittest.TestCase):
    def test_default_eligibility_and_readiness(self):
        resources = render()
        ds = resources["DaemonSet"]
        pod = ds["spec"]["template"]["spec"]
        self.assertNotIn("nodeSelector", pod)
        self.assertNotIn("tolerations", pod)
        terms = pod["affinity"]["nodeAffinity"][
            "requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
        self.assertEqual(len(terms), 1)
        exprs = {e["key"]: e for e in terms[0]["matchExpressions"]}
        self.assertEqual(exprs["kubernetes.io/os"]["values"], ["linux"])
        self.assertEqual(exprs["kubernetes.io/arch"]["values"], ["amd64", "arm64"])
        self.assertEqual(exprs["gvisor.dev/install"]["operator"], "NotIn")
        self.assertEqual(exprs["gvisor.dev/install"]["values"], ["disabled"])
        self.assertEqual(resources["RuntimeClass"]["scheduling"]["nodeSelector"],
                         {"gvisor.dev/ready": "true"})
        self.assertEqual(ds["spec"]["updateStrategy"]["rollingUpdate"], {"maxUnavailable": 1})

    def test_custom_paths_share_host_lock_and_selection_constraints(self):
        resources = render({
            "nodeSelector": {"pool": "sandbox"},
            "containerd": {"config": "/custom/config.toml", "socket": "/custom/runtime.sock"},
            "installDir": "/custom/bin",
        })
        pod = resources["DaemonSet"]["spec"]["template"]["spec"]
        self.assertEqual(pod["nodeSelector"], {"pool": "sandbox"})
        self.assertIn("affinity", pod)
        self.assertTrue(pod["hostPID"])
        agent = pod["containers"][0]
        self.assertTrue(agent["securityContext"]["privileged"])
        env = {e["name"]: e.get("value") for e in agent["env"]}
        self.assertEqual(env["CONTAINERD_CONFIG"], "/custom/config.toml")
        self.assertEqual(env["INSTALL_DIR"], "/custom/bin")
        host = next(v for v in pod["volumes"] if v["name"] == "host")
        self.assertEqual(host["hostPath"], {"path": "/", "type": "Directory"})
        self.assertIn({"name": "host", "mountPath": "/host"}, agent["volumeMounts"])
        self.assertNotIn("hostNetwork", pod)

    def test_cluster_singleton_and_least_api_permissions(self):
        first = render()
        second = render({"runtimeClassName": "other", "handler": "other"}, release="second")
        for kind in ("ClusterRole", "ClusterRoleBinding"):
            self.assertEqual(first[kind]["metadata"]["name"], second[kind]["metadata"]["name"])
        rules = first["ClusterRole"]["rules"] + first["Role"]["rules"]
        self.assertEqual({r for rule in rules for r in rule["resources"]}, {"nodes", "events"})
        self.assertFalse({"list", "watch", "delete"} & {v for rule in rules for v in rule["verbs"]})
        for resource in first.values():
            self.assertNotIn("helm.sh/hook", resource["metadata"].get("annotations", {}))

    def test_release_version_and_payload_are_explicit(self):
        resources = render({"image": {"tag": "release-20261005.2"}})
        agent = resources["DaemonSet"]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(agent["image"], "example.invalid/gvisor:release-20261005.2")
        self.assertEqual(agent["command"], ["/usr/local/bin/nodeinstaller"])
        self.assertEqual(agent["readinessProbe"]["httpGet"]["path"], "/readyz")
        self.assertEqual(agent["livenessProbe"]["httpGet"]["path"], "/healthz")

    def test_reject_relative_host_path(self):
        with self.assertRaises(subprocess.CalledProcessError):
            render({"installDir": "relative"})

    def test_published_chart_defaults_to_matching_release(self):
        with tempfile.TemporaryDirectory() as directory:
            chart = pathlib.Path(directory) / "gvisor"
            shutil.copytree(CHART, chart)
            metadata = yaml.safe_load((chart / "Chart.yaml").read_text())
            metadata.update(version="20261005.2.0", appVersion="release-20261005.2")
            (chart / "Chart.yaml").write_text(yaml.safe_dump(metadata))
            resources = render(chart=chart)
        agent = resources["DaemonSet"]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(agent["image"], "example.invalid/gvisor:release-20261005.2")

    def test_source_chart_requires_image_repository(self):
        result = subprocess.run(["helm", "template", "test", str(CHART)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image.repository must name the installer image", result.stderr)

    def test_lint(self):
        subprocess.run(["helm", "lint", str(CHART), "--set",
                        "image.repository=example.invalid/gvisor"], check=True,
                       capture_output=True)


if __name__ == "__main__":
    unittest.main()
