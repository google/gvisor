#!/bin/bash

# This file sets up all the postsubmit hooks for a given repository on GitHub,
# using Google Cloud Build. The GitHub repository must be mirrored to the Google
# Cloud project and the Cloud Build API must be enabled.
#
# Both the build badge bucket and release buckets must exist and have
# appropriate permissions: the cloud build service account in this project
# should have Object Creator capabilities. Note this is the reason this project
# must be separate from the presubmit workflows, only the service account within
# this project should have these permissions.

set -xeo pipefail

declare -r PROJECT=${PROJECT:-gvisor-release}
declare -r REPO=${REPO:-gvisor}
declare -r OWNER=${OWNER:-google}
declare -r BUCKET=${BUCKET:-gvisor-build-badges}
declare -r RBE_PROJECT=${RBE_PROJECT:-gvisor-rbe}
declare -r POSTSUBMIT_OPTS=(
    alpha
    builds
    triggers
    create
    github
    --repo_name="${REPO}"
    --repo_owner="${OWNER}"
    --branch_pattern="master"
)

# Build badge.
gcloud ${POSTSUBMIT_OPTS[@]} --build_config=cloudbuild/build.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}"

# Go branch.
gcloud ${POSTSUBMIT_OPTS[@]} --build_config=cloudbuild/go.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}"

# Release artifacts.
gcloud ${POSTSUBMIT_OPTS[@]} --build_config=cloudbuild/release.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}"
