#!/bin/bash

# This file sets up all the postsubmit hooks for a given repository on GitHub,
# using Google Cloud Build. The GitHub repository must be mirrored to the
# Google Cloud project and the Cloud Build API must be enabled.
#
# Both the build badge bucket and release buckets must exist and have
# appropriate permissions: the cloud build service account in this project
# should have Object Creator capabilities. Note this is the reason this project
# must be separate from the presubmit workflows, only the service account
# within this project should have these permissions.

set -xeo pipefail

declare -r PROJECT=${PROJECT:-gvisor-release}
declare -r REPO=${REPO:-gvisor}
declare -r OWNER=${OWNER:-google}
declare -r BADGE_BUCKET=${BADGE_BUCKET:-gvisor-build-badges}
declare -r RELEASE_BUCKET=${RELEASE_BUCKET:-gvisor}
declare -r RBE_PROJECT=${RBE_PROJECT:-gvisor-rbe}
declare -r GO_ORIGIN=${GO_ORIGIN:-origin}
declare -r POSTSUBMIT_OPTS=(
    alpha
    builds
    triggers
    create
    github
    --project="${PROJECT}"
    --repo_name="${REPO}"
    --repo_owner="${OWNER}"
)

# Build badge.
gcloud ${POSTSUBMIT_OPTS[@]} --build_config=cloudbuild/build.yaml --branch_pattern="master" --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_BUCKET="${BADGE_BUCKET}"

# Go branch.
gcloud ${POSTSUBMIT_OPTS[@]} --build_config=cloudbuild/go.yaml --branch_pattern="master" --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_ORIGIN="${GO_ORIGIN}"

# Release artifacts.
gcloud ${POSTSUBMIT_OPTS[@]} --build_config=cloudbuild/release.yaml --branch_pattern="master" --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_BUCKET="${RELEASE_BUCKET}",_LATEST="true"
gcloud ${POSTSUBMIT_OPTS[@]} --build_config=cloudbuild/release.yaml --tag_pattern="release-.*" --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_BUCKET="${RELEASE_BUCKET}",_TAG="true",_DATE="true"
