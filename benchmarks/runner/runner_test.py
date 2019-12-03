# python3
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Top-level tests."""

import os
import subprocess
import sys

from click import testing
import pytest

from benchmarks import runner


def _get_locale():
  output = subprocess.check_output(["locale", "-a"])
  locales = output.split()
  if b"en_US.utf8" in locales:
    return "en_US.UTF-8"
  else:
    return "C.UTF-8"


def _set_locale():
  locale = _get_locale()
  if os.getenv("LANG") != locale:
    os.environ["LANG"] = locale
    os.environ["LC_ALL"] = locale
    os.execv("/proc/self/exe", ["python"] + sys.argv)


def test_list():
  cli_runner = testing.CliRunner()
  result = cli_runner.invoke(runner.runner, ["list"])
  print(result.output)
  assert result.exit_code == 0


def test_run():
  cli_runner = testing.CliRunner()
  result = cli_runner.invoke(runner.runner, ["run", "--mock", "."])
  print(result.output)
  assert result.exit_code == 0


if __name__ == "__main__":
  _set_locale()
  sys.exit(pytest.main([__file__]))
