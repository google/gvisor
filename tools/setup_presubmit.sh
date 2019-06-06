#!/bin/bash

# This file sets up all the presubmit hooks for a given repository on GitHub,
# using Google Cloud Build. The Google Cloud Build application must be installed
# on the repository and associated with the given project.
#
# Note that the gcloud tool does not support setting names on the hooks yet. It
# is expected that you will manually edit the names for esthetics. This file
# exists primarily to serve as documentation and automation help.

set -xeo pipefail

declare -r PROJECT=${PROJECT:-gvisor-presubmit}
declare -r REPO=${REPO:-gvisor}
declare -r OWNER=${OWNER:-google}
declare -r RBE_PROJECT=${RBE_PROJECT:-gvisor-rbe}
declare -r PRESUBMIT_OPTS=(
    alpha
    builds
    triggers
    create
    github
    --repo_name="${REPO}"
    --repo_owner="${OWNER}"
    --comment_control
)

# Tests.
gcloud ${PRESUBMIT_OPTS[@]} --build_config=cloudbuild/test.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}"
gcloud ${PRESUBMIT_OPTS[@]} --build_config=cloudbuild/script.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_SCRIPT=test/docker_tests.sh
gcloud ${PRESUBMIT_OPTS[@]} --build_config=cloudbuild/script.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_SCRIPT=test/do_tests.sh
gcloud ${PRESUBMIT_OPTS[@]} --build_config=cloudbuild/script.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_SCRIPT=test/kvm_tests.sh
gcloud ${PRESUBMIT_OPTS[@]} --build_config=cloudbuild/script.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_SCRIPT=test/make_tests.sh
gcloud ${PRESUBMIT_OPTS[@]} --build_config=cloudbuild/script.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_SCRIPT=test/root_tests.sh
gcloud ${PRESUBMIT_OPTS[@]} --build_config=cloudbuild/script.yaml --substitutions=_RBE_PROJECT="${RBE_PROJECT}",_SCRIPT=test/simple_tests.sh

# Go validation.
gcloud ${PRESUBMIT_OPTS[@]} --build_config=cloudbuild/go.yaml
