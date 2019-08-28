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

# This script is responsible for building a new GCP image that: 1) has nested
# virtualization enabled, and 2) has been completely set up with the
# image_setup.sh script. This script should be idempotent, as we memoize the
# setup script with a hash and check for that name.
#
# The GCP project name should be defined via a gcloud config.

set -xeo pipefail

# Parameters.
declare -r ZONE=${ZONE:-us-central1-f}
declare -r USERNAME=${USERNAME:-test}
declare -r IMAGE_PROJECT=${IMAGE_PROJECT:-ubuntu-os-cloud}
declare -r IMAGE_FAMILY=${IMAGE_FAMILY:-ubuntu-1604-lts}

# Random names.
declare -r DISK_NAME=$(mktemp -u disk-XXXXXX | tr A-Z a-z)
declare -r SNAPSHOT_NAME=$(mktemp -u snapshot-XXXXXX | tr A-Z a-z)
declare -r INSTANCE_NAME=$(mktemp -u build-XXXXXX | tr A-Z a-z)

# Hashes inputs.
declare -r SETUP_BLOB=$(echo ${ZONE} ${USERNAME} ${IMAGE_PROJECT} ${IMAGE_FAMILY} && sha256sum "$@")
declare -r SETUP_HASH=$(echo ${SETUP_BLOB} | sha256sum - | cut -d' ' -f1 | cut -c 1-16)
declare -r IMAGE_NAME=${IMAGE_NAME:-image-}${SETUP_HASH}

# Does the image already exist? Skip the build.
declare -r existing=$(gcloud compute images list --filter="name=(${IMAGE_NAME})" --format="value(name)")
if ! [[ -z "${existing}" ]]; then
  echo "${existing}"
  exit 0
fi

# Set the zone for all actions.
gcloud config set compute/zone "${ZONE}"

# Start a unique instance. Note that this instance will have a unique persistent
# disk as it's boot disk with the same name as the instance.
gcloud compute instances create \
    --quiet \
    --image-project "${IMAGE_PROJECT}" \
    --image-family "${IMAGE_FAMILY}" \
    --boot-disk-size "200GB" \
    "${INSTANCE_NAME}"
function cleanup {
    gcloud compute instances delete --quiet "${INSTANCE_NAME}"
}
trap cleanup EXIT

# Wait for the instance to become available.
declare attempts=0
while [[ "${attempts}" -lt 30 ]]; do
  attempts=$((${attempts}+1))
  if gcloud compute ssh "${USERNAME}"@"${INSTANCE_NAME}" -- true; then
    break
  fi
done
if [[ "${attempts}" -ge 30 ]]; then
  echo "too many attempts: failed"
  exit 1
fi

# Run the install scripts provided.
for arg; do
  gcloud compute ssh "${USERNAME}"@"${INSTANCE_NAME}" -- sudo bash - <"${arg}"
done

# Stop the instance; required before creating an image.
gcloud compute instances stop --quiet "${INSTANCE_NAME}"

# Create a snapshot of the instance disk.
gcloud compute disks snapshot \
    --quiet \
    --zone="${ZONE}" \
    --snapshot-names="${SNAPSHOT_NAME}" \
    "${INSTANCE_NAME}"

# Create the disk image.
gcloud compute images create \
    --quiet \
    --source-snapshot="${SNAPSHOT_NAME}" \
    --licenses="https://www.googleapis.com/compute/v1/projects/vm-options/global/licenses/enable-vmx" \
    "${IMAGE_NAME}"
