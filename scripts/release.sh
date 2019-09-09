#!/bin/bash

# Copyright 2018 The gVisor Authors.
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

source $(dirname $0)/common.sh

# Tag a release only if provided.
if ! [[ -v KOKORO_RELEASE_COMMIT ]]; then
  echo "No KOKORO_RELEASE_COMMIT provided." >&2
  exit 1
fi
if ! [[ -v KOKORO_RELEASE_TAG ]]; then
  echo "No KOKORO_RELEASE_TAG provided." >&2
  exit 1
fi

# Unless an explicit releaser is provided, use the bot e-mail.
declare -r KOKORO_RELEASE_AUTHOR=${KOKORO_RELEASE_AUTHOR:-gvisor-bot}
declare -r EMAIL=${EMAIL:-${KOKORO_RELEASE_AUTHOR}@google.com}

# Ensure we have an appropriate configuration for the tag.
git config --get user.name || git config user.name "gVisor-bot"
git config --get user.email || git config user.email "${EMAIL}"

# Run the release tool, which pushes to the origin repository.
tools/tag_release.sh "${KOKORO_RELEASE_COMMIT}" "${KOKORO_RELEASE_TAG}"
