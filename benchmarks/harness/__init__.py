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
"""Core benchmark utilities."""

import getpass
import os

# LOCAL_WORKLOADS_PATH defines the path to use for local workloads. This is a
# format string that accepts a single string parameter.
LOCAL_WORKLOADS_PATH = os.path.join(
    os.path.dirname(__file__), "../workloads/{}/tar.tar")

# REMOTE_WORKLOADS_PATH defines the path to use for storing the workloads on the
# remote host. This is a format string that accepts a single string parameter.
REMOTE_WORKLOADS_PATH = "workloads/{}"

# DEFAULT_USER is the default user running this script.
DEFAULT_USER = getpass.getuser()

# DEFAULT_USER_HOME is the home directory of the user running the script.
DEFAULT_USER_HOME = os.environ["HOME"] if "HOME" in os.environ else ""
