#!/usr/bin/env python3
# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
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

"""Check failed adoption cleanup against a complete installed runsc release.

Requires root, gcc with static libc, and a reflink filesystem for --work-dir.
Create nonempty ordinary and external split checkpoints, reject the ordinary
image with clone and consume adoption, and compare the complete input files
after deleting each failed container. Also verify successful restores and
isolation between two clones of the same template.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runsc", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid():
        parser.error("requires root")
    args.work_dir.mkdir(exist_ok=False)
    args.output.mkdir(parents=True, exist_ok=True)
    rootfs = args.work_dir / "rootfs"
    rootfs.mkdir()
    (rootfs / "proc").mkdir()
    subprocess.run(["gcc", "-O2", "-static", str(Path(__file__).with_name("workload.c")),
                    "-o", str(rootfs / "workload")], check=True)
    bundle = args.work_dir / "bundle"
    bundle.mkdir()
    size = 1 << 20
    spec = {"ociVersion": "1.0.2", "process": {"terminal": False,
            "user": {"uid": 0, "gid": 0}, "args": ["/workload", "serve", str(size)],
            "env": [], "cwd": "/"}, "root": {"path": str(rootfs), "readonly": False},
            "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"}],
            "linux": {"namespaces": [{"type": item} for item in ["pid", "mount", "ipc", "uts", "network"]]}}
    (bundle / "config.json").write_text(json.dumps(spec))
    common = [str(args.runsc), f"--root={args.work_dir / 'runtime'}", "--platform=systrap",
              "--network=none", "--filestore-reflink=enabled", f"--overlay2=all:dir={args.work_dir / 'stores'}",
              "--debug", f"--debug-log={args.output}/"]
    (args.work_dir / "stores").mkdir()
    prefix = "adoptcheck-" + hashlib.sha256(str(args.work_dir).encode()).hexdigest()[:12] + "-"
    ids = set()

    def run(command, extra=(), success=True):
        command = [prefix + item[1:] if item.startswith("@") else item for item in command]
        ids.update(item for item in command if item.startswith(prefix))
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(common + list(extra) + command, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=180)
            output.seek(0)
            result.output = output.read()
        with (args.output / "commands.log").open("ab") as log:
            log.write((json.dumps(list(extra) + command) + "\n").encode() + result.output)
        if success and result.returncode:
            raise RuntimeError(f"command failed: {command}: {result.output.decode(errors='replace')}")
        return result

    def inventory():
        files = {}
        for file in sorted(snapshot.iterdir()):
            if file.is_file():
                with file.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                files[file.name] = {"size": file.stat().st_size, "sha256": digest}
        return files

    ordinary = args.work_dir / "ordinary"
    external = args.work_dir / "external"
    snapshot = args.work_dir / "snapshot"
    outcomes = []
    try:
        for label, image in [("ordinary", ordinary), ("external", external)]:
            image.mkdir()
            run(["run", "--detach", f"--bundle={bundle}", "@" + label])
            deadline = time.monotonic() + 120
            while run(["exec", "@" + label, "/workload", "ready"], success=False).returncode:
                if time.monotonic() > deadline:
                    raise RuntimeError("workload did not become ready")
                time.sleep(0.05)
            options = ["--skip-filestore-pages", f"--filestore-snapshot-dir={snapshot}"] if label == "external" else []
            run(["checkpoint", f"--image-path={image}", "--fs-checkpoint-paths=/"] + options + ["@" + label])
            run(["delete", "--force", "@" + label])
        before = inventory()
        if not any(item["size"] > size for item in before.values()):
            raise RuntimeError("external artifact is empty")
        for mode in ["clone", "consume"]:
            extra = [f"--filestore-adopt-dir={snapshot}", f"--filestore-adopt-mode={mode}"]
            cid = "@rejected-" + mode
            result = run(["restore", "--detach", f"--bundle={bundle}", f"--image-path={ordinary}", cid],
                         extra=extra, success=False)
            if not result.returncode:
                raise RuntimeError("ordinary checkpoint unexpectedly accepted adoption")
            run(["delete", "--force", cid], success=False)
            if b"cannot load ordinary checkpoint" not in result.output:
                raise RuntimeError(f"{mode} restore failed without reaching adoption format validation")
            if inventory() != before:
                raise RuntimeError(f"failed {mode} restore modified an input artifact")
            outcomes.append({"name": "ordinary_rejected_" + mode, "input_preserved": True})
        extra = [f"--filestore-adopt-dir={snapshot}"]
        for cid in ["@first", "@second"]:
            run(["restore", "--detach", f"--bundle={bundle}", f"--image-path={external}", cid], extra=extra)
            run(["exec", cid, "/workload", "verify", str(size)])
            run(["exec", cid, "/workload", "unmarked"])
            run(["exec", cid, "/workload", "mark"])
        for cid in ["@first", "@second"]:
            run(["delete", "--force", cid])
        if inventory() != before:
            raise RuntimeError("destroying a restored clone modified its template")
        outcomes.append({"name": "external_clone_isolation", "verified_bytes_per_clone": size})
        run(["restore", "--detach", f"--bundle={bundle}", f"--image-path={external}", "@consumed"],
            extra=extra + ["--filestore-adopt-mode=consume"])
        run(["exec", "@consumed", "/workload", "verify", str(size)])
        run(["delete", "--force", "@consumed"])
        outcomes.append({"name": "external_consume", "verified_bytes": size})
        (args.output / "results.json").write_text(json.dumps({"passed": True, "outcomes": outcomes,
                                                            "initial_artifacts": before}, indent=2) + "\n")
        print(json.dumps(outcomes), flush=True)
    finally:
        for cid in sorted(ids):
            run(["delete", "--force", cid], success=False)


if __name__ == "__main__":
    main()
