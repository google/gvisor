#!/bin/bash

# Copyright 2019 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

bazel version
python3 -V

readonly KYTHE_VERSION='v0.0.38'
readonly WORKDIR="$(mktemp -d)"
readonly KYTHE_DIR="${WORKDIR}/kythe-${KYTHE_VERSION}"
if [[ -n "$KOKORO_GIT_COMMIT" ]]; then
  readonly KZIP_FILENAME="${KOKORO_ARTIFACTS_DIR}/${KOKORO_GIT_COMMIT}.kzip"
else
  readonly KZIP_FILENAME="$(git rev-parse HEAD).kzip"
fi

wget -q -O "${WORKDIR}/kythe.tar.gz" \
  "https://github.com/kythe/kythe/releases/download/${KYTHE_VERSION}/kythe-${KYTHE_VERSION}.tar.gz"
tar --no-same-owner -xzf "${WORKDIR}/kythe.tar.gz" --directory "$WORKDIR"

if [[ -n "$KOKORO_ARTIFACTS_DIR" ]]; then
  cd "${KOKORO_ARTIFACTS_DIR}/github/gvisor"
fi
bazel \
  --bazelrc="${KYTHE_DIR}/extractors.bazelrc" \
  build \
  --override_repository kythe_release="${KYTHE_DIR}" \
  --define=kythe_corpus=gvisor.dev \
  //...

"${KYTHE_DIR}/tools/kzip" merge \
  --output "$KZIP_FILENAME" \
  $(find -L bazel-out/*/extra_actions/ -name '*.kzip')
