#!/bin/bash

# Copyright 2019 The gVisor Authors.
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

DIR=$(dirname $0)
source "${DIR}"/common.sh

# Provide a credential file if available.
export OAUTH_TOKEN_FILE=""
if [[ -v KOKORO_GITHUB_ACCESS_TOKEN ]]; then
  OAUTH_TOKEN_FILE="${KOKORO_KEYSTORE_DIR}/${KOKORO_GITHUB_ACCESS_TOKEN}"
fi

REPO_ROOT=$(cd "$(dirname "${DIR}")"; pwd)
run //tools/issue_reviver:issue_reviver --path "${REPO_ROOT}" --oauth-token-file="${OAUTH_TOKEN_FILE}"
