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

# Required input.
if ! [[ -v IMAGE ]]; then
  echo "no image provided: set IMAGE."
  exit 1
fi

# Parameters.
declare -r USERNAME=${USERNAME:-test}
declare -r KEYNAME=$(mktemp --tmpdir -u key-XXXXXX)
declare -r SSHKEYS=$(mktemp --tmpdir -u sshkeys-XXXXXX)
declare -r INSTANCE_NAME=$(mktemp -u test-XXXXXX | tr A-Z a-z)
declare -r MACHINE=${MACHINE:-n1-standard-1}
declare -r ZONE=${ZONE:-us-central1-f}
declare -r SUDO=${SUDO:-false}

# Standard arguments (applies only on script execution).
declare -ar SSH_ARGS=("-o" "ConnectTimeout=60" "--")

# This script is executed as a test rule, which will reset the value of HOME.
# Unfortunately, it is needed to load the gconfig credentials. We will reset
# HOME when we actually execute in the remote environment, defined below.
export HOME=$(eval echo ~$(whoami))

# Generate unique keys for this test.
[[ -f "${KEYNAME}" ]] || ssh-keygen -t rsa -N "" -f "${KEYNAME}" -C "${USERNAME}"
cat > "${SSHKEYS}" <<EOF
${USERNAME}:$(cat ${KEYNAME}.pub)
EOF

# Start a unique instance. This means that we first generate a unique set of ssh
# keys to ensure that only we have access to this instance. Note that we must
# constrain ourselves to Haswell or greater in order to have nested
# virtualization available.
gcloud compute instances create \
    --min-cpu-platform "Intel Haswell" \
    --preemptible \
    --no-scopes \
    --metadata block-project-ssh-keys=TRUE \
    --metadata-from-file ssh-keys="${SSHKEYS}" \
    --machine-type "${MACHINE}" \
    --image "${IMAGE}" \
    --zone "${ZONE}" \
    "${INSTANCE_NAME}"
function cleanup {
    gcloud compute instances delete --quiet --zone "${ZONE}" "${INSTANCE_NAME}"
}
trap cleanup EXIT

# Wait for the instance to become available (up to 5 minutes).
declare timeout=300
declare success=0
declare -r start=$(date +%s)
declare -r end=$((${start}+${timeout}))
while [[ "$(date +%s)" -lt "${end}" ]] && [[ "${success}" -lt 3 ]]; do
  if gcloud compute ssh --ssh-key-file="${KEYNAME}" --zone "${ZONE}" "${USERNAME}"@"${INSTANCE_NAME}" -- true 2>/dev/null; then
    success=$((${success}+1))
  fi
done
if [[ "${success}" -eq "0" ]]; then
  echo "connect timed out after ${timeout} seconds."
  exit 1
fi

# Copy the local directory over.
tar czf - --dereference --exclude=.git . |
    gcloud compute ssh \
        --ssh-key-file="${KEYNAME}" \
        --zone "${ZONE}" \
        "${USERNAME}"@"${INSTANCE_NAME}" -- \
        "${SSH_ARGS[@]}" \
        tar xzf -

# Execute the command remotely.
for cmd; do
  # Setup relevant environment.
  #
  # N.B. This is not a complete test environment, but is complete enough to
  # provide rudimentary sharding and test output support.
  declare -a PREFIX=( "env" )
  if [[ -v TEST_SHARD_INDEX ]]; then
    PREFIX+=( "TEST_SHARD_INDEX=${TEST_SHARD_INDEX}" )
  fi
  if [[ -v TEST_SHARD_STATUS_FILE ]]; then
    SHARD_STATUS_FILE=$(mktemp -u test-shard-status-XXXXXX)
    PREFIX+=( "TEST_SHARD_STATUS_FILE=/tmp/${SHARD_STATUS_FILE}" )
  fi
  if [[ -v TEST_TOTAL_SHARDS ]]; then
    PREFIX+=( "TEST_TOTAL_SHARDS=${TEST_TOTAL_SHARDS}" )
  fi
  if [[ -v TEST_TMPDIR ]]; then
    REMOTE_TMPDIR=$(mktemp -u test-XXXXXX)
    PREFIX+=( "TEST_TMPDIR=/tmp/${REMOTE_TMPDIR}" )
    # Create remotely.
    gcloud compute ssh \
      --ssh-key-file="${KEYNAME}" \
      --zone "${ZONE}" \
      "${USERNAME}"@"${INSTANCE_NAME}" -- \
      "${SSH_ARGS[@]}" \
      mkdir -p "/tmp/${REMOTE_TMPDIR}"
  fi
  if [[ -v XML_OUTPUT_FILE ]]; then
    TEST_XML_OUTPUT=$(mktemp -u xml-output-XXXXXX)
    PREFIX+=( "XML_OUTPUT_FILE=/tmp/${TEST_XML_OUTPUT}" )
  fi
  if [[ "${SUDO}" == "true" ]]; then
    PREFIX+=( "sudo" "-E" )
  fi

  # Execute the command.
  gcloud compute ssh \
    --ssh-key-file="${KEYNAME}" \
    --zone "${ZONE}" \
    "${USERNAME}"@"${INSTANCE_NAME}" -- \
    "${SSH_ARGS[@]}" \
    "${PREFIX[@]}" "${cmd}"

  # Collect relevant results.
  if [[ -v TEST_SHARD_STATUS_FILE ]]; then
    gcloud compute scp \
        --ssh-key-file="${KEYNAME}" \
        --zone "${ZONE}" \
        "${USERNAME}"@"${INSTANCE_NAME}":/tmp/"${SHARD_STATUS_FILE}" \
        "${TEST_SHARD_STATUS_FILE}" 2>/dev/null || true # Allowed to fail.
  fi
  if [[ -v XML_OUTPUT_FILE ]]; then
    gcloud compute scp \
        --ssh-key-file="${KEYNAME}" \
        --zone "${ZONE}" \
        "${USERNAME}"@"${INSTANCE_NAME}":/tmp/"${TEST_XML_OUTPUT}" \
        "${XML_OUTPUT_FILE}" 2>/dev/null || true # Allowed to fail.
  fi

  # Clean up the temporary directory.
  if [[ -v TEST_TMPDIR ]]; then
    gcloud compute ssh \
      --ssh-key-file="${KEYNAME}" \
      --zone "${ZONE}" \
      "${USERNAME}"@"${INSTANCE_NAME}" -- \
      "${SSH_ARGS[@]}" \
      rm -rf "/tmp/${REMOTE_TMPDIR}"
  fi
done
