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

set -xeo pipefail

# Parameters.
declare -r ZONE=${ZONE:-us-central1-f}
declare -r USERNAME=${USERNAME:-test}
declare -r KEYNAME=${KEYNAME:-local-key}
declare -r INSTANCE_NAME=$(mktemp -u test-XXXXXX | tr A-Z a-z)

# Set the zone for all actions.
gcloud config set compute/zone "${ZONE}"

# Generate unique keys for this test.
[[ -f "${KEYNAME}" ]] || ssh-keygen -t rsa -N "" -f "${KEYNAME}" -C "${USERNAME}"
cat > ssh-keys <<EOF
${USERNAME}:$(cat ${KEYNAME}.pub)
EOF

# First: create an image if required. The build image script will ensure that
# bazel is available, but in general any other dependencies need to be installed
# by the script being executed.
declare -r IMAGE=$(tools/image_build.sh "$@")

# Second: start a unique instance. This means that we first generate a unique
# set of ssh keys to ensure that only we have access to this instance. Note that
# we must constrain ourselves to Haswell or greater in order to have nested
# virtualization available.
gcloud compute instances create \
    --min-cpu-platform "Intel Haswell" \
    --preemptible \
    --no-scopes \
    --metadata block-project-ssh-keys=TRUE \
    --metadata-from-file ssh-keys=ssh-keys \
    --image "${IMAGE}" \
    "${INSTANCE_NAME}"
function cleanup {
    gcloud compute instances delete --quiet "${INSTANCE_NAME}"
}
trap cleanup EXIT

# Wait for the instance to before available.
attempts=0
while [[ ${attempts} -lt 30 ]]; do
  attempts=$(($attempts+1))
  if gcloud compute ssh --ssh-key-file="${KEYNAME}" "${USERNAME}"@"${INSTANCE_NAME}" -- true; then
    break
  fi
done
if [[ ${attempts} -ge 30 ]]; then
  echo "too many attempts: failed"
  exit 1
fi

# Copy the local directory over.
tar czf - --exclude=.git . |
    gcloud compute ssh \
        --ssh-key-file="${KEYNAME}" \
        "${USERNAME}"@"${INSTANCE_NAME}" -- tar xzf -

# Execute the command remotely. We include the RBE_PROJECT_ID environment
# variable here specifically, as that is passed through to the test scripts and
# picked up by the test/common.sh harness for remote execution.
timeout --signal=KILL $((60 * 60)) \
     gcloud compute ssh \
    --ssh-key-file="${KEYNAME}" \
    "${USERNAME}"@"${INSTANCE_NAME}" -- env RBE_PROJECT_ID="${RBE_PROJECT_ID}" "$@"

# Copy everything back.
gcloud compute ssh \
    --ssh-key-file="${KEYNAME}" \
    "${USERNAME}"@"${INSTANCE_NAME}" -- tar czf - --exclude=.git . | \
        tar xzf -
