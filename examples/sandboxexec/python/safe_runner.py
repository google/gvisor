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

"""Example CLI demonstrating safe script execution using gVisor SandboxExec."""

import argparse
import os
import sys
from typing import List, Optional, Tuple, Union

from gvisor import sandbox


def run_in_sandbox(
    code: Optional[str] = None,
    script_path: Optional[str] = None,
    output_dir: Optional[str] = None,
    timeout: float = 5.0,
    network: Union[sandbox.NetworkMode, str] = sandbox.NetworkMode.NONE,
    working_dir: str = "/",
    env: Optional[List[str]] = None,
    interpreter: str = "python3",
) -> Tuple[int, str, str]:
  """Executes code or a script file inside an isolated gVisor sandbox.

  Args:
    code: Inline code string to execute.
    script_path: Path to a host script file to execute.
    output_dir: Host directory mounted read-write to /output inside sandbox.
    timeout: Maximum execution timeout in seconds.
    network: Network mode ('none', 'sandbox', 'host', or NetworkMode enum).
    working_dir: Initial working directory inside container.
    env: List of environment variables in KEY=VALUE format.
    interpreter: Command/interpreter to run code or script (default: 'python3').

  Returns:
    A tuple of (exit_code, stdout, stderr).
  """
  mounts = [
      sandbox.Mount.tmpfs("/tmp"),
      sandbox.Mount.proc("/proc"),
  ]

  if output_dir:
    os.makedirs(output_dir, exist_ok=True)
    mounts.append(
        sandbox.Mount.bind(
            source=os.path.abspath(output_dir),
            destination="/output",
            readonly=False,
        )
    )

  if script_path:
    abs_script = os.path.abspath(script_path)
    script_dir, script_name = os.path.split(abs_script)
    mounts.append(
        sandbox.Mount.bind(
            source=script_dir,
            destination="/scripts",
            readonly=True,
        )
    )
    cmd = [interpreter, f"/scripts/{script_name}"]
  elif code:
    cmd = [interpreter, "-c", code]
  else:
    raise ValueError("Either code or script_path must be provided.")

  try:
    with sandbox.Sandbox(
        network=network,
        working_dir=working_dir,
        mounts=mounts,
        env=env,
    ) as sb:
      stdout, stderr = sb.exec(cmd[0], *cmd[1:], timeout=timeout)
      return 0, stdout, stderr
  except sandbox.Error as e:
    return 1, "", str(e)


def main():
  parser = argparse.ArgumentParser(
      description="Run untrusted code in an isolated gVisor sandbox."
  )
  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument("-c", "--code", help="Inline code snippet to execute.")
  group.add_argument(
      "-s", "--script", help="Path to host script file to execute."
  )

  parser.add_argument(
      "-i",
      "--interpreter",
      default="python3",
      help="Interpreter binary to run with (default: python3).",
  )
  parser.add_argument(
      "-o", "--output-dir", help="Host directory mounted read-write to /output."
  )
  parser.add_argument(
      "-t",
      "--timeout",
      type=float,
      default=5.0,
      help="Timeout in seconds (default: 5.0).",
  )
  parser.add_argument(
      "-n",
      "--network",
      default="none",
      choices=["none", "sandbox", "host"],
      help=(
          "Network mode: 'none' (default, isolated), 'sandbox' (isolated"
          " netstack, requires root), 'host' (shares host network)."
      ),
  )
  parser.add_argument(
      "-w",
      "--working-dir",
      default="/",
      help="Working directory in container (default: /).",
  )
  parser.add_argument(
      "-e",
      "--env",
      action="append",
      help="Environment variable (KEY=VALUE). Can be repeated.",
  )

  args = parser.parse_args()

  code, stdout, stderr = run_in_sandbox(
      code=args.code,
      script_path=args.script,
      output_dir=args.output_dir,
      timeout=args.timeout,
      network=args.network,
      working_dir=args.working_dir,
      env=args.env,
      interpreter=args.interpreter,
  )

  if stdout:
    print(stdout, end="" if stdout.endswith("\n") else "\n")
  if stderr:
    print(f"Error: {stderr}", file=sys.stderr)

  sys.exit(code)


if __name__ == "__main__":
  main()
