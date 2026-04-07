#!/bin/bash
#
# Copyright 2026 The gVisor Authors.
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
#
# gcs_fuse_test_execution_script - automates GCSFUSE compatibility test with gVisor.
# Sets a unique bucket name, checks for ADC credentials, builds the test
# Docker image, and runs it using the 'runsc' runtime.

set -e

# Configuration
RUNTIME="${GVISOR_RUNTIME:-runsc}"
GCS_BUCKET="gvisor-fuse-test-$(date +%s)"
ADC_PATH="$HOME/.config/gcloud/application_default_credentials.json"
IMAGE_NAME="gcsfuse-tester"

# Find the directory of this script to locate the Dockerfile and test script.
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# 1. Check for Prerequisites
if ! docker info | grep -q "$RUNTIME"; then
  echo "Error: gVisor runtime '$RUNTIME' not found in Docker info."
  echo "Please ensure gVisor is installed and configured as a Docker runtime."
  exit 1
fi

# Application Default Credentials check.
if [[ ! -f "$ADC_PATH" ]]; then
  echo "Application Default Credentials (ADC) not found at $ADC_PATH."
  echo "Running 'gcloud auth application-default login'..."
  # If the user is running this in a CI environment, then they should
  # provide ADC through alternate methods.
  gcloud auth application-default login
fi

# 2. Preparation: Create GCS Bucket
echo "Creating GCS bucket: gs://$GCS_BUCKET"
gcloud storage buckets create "gs://$GCS_BUCKET"

# Register a cleanup trap to ensure the bucket is deleted even on failure.
cleanup() {
  echo ""
  echo "Cleaning up GCS bucket: gs://$GCS_BUCKET"
  gcloud storage buckets delete "gs://$GCS_BUCKET" --quiet
}
trap cleanup EXIT

# 3. Build the Image
echo "Building Docker image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

# 4. Run the Test
echo "Running the test with gVisor ($RUNTIME)..."
# We use --privileged to allow mounting within the container.
# We mount the host's ADC into the container to allow gcsfuse to authenticate.
docker run --privileged --runtime="$RUNTIME" \
  -e "GCS_BUCKET=$GCS_BUCKET" \
  -e "GOOGLE_APPLICATION_CREDENTIALS=/tmp/adc.json" \
  -v "$ADC_PATH:/tmp/adc.json" \
  "$IMAGE_NAME"

echo "Test successfully completed!"
