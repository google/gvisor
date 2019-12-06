#!/bin/bash

set -xeo pipefail

declare -r PROJECT=${PROJECT:-ascannell-dev}
declare -r OWNER=${OWNER:-amscanne}
declare -r REPO=${REPO:-gvisor}

gcloud beta builds triggers import --project="${PROJECT}" --source=<(cat <<EOF
name: presubmit
github:
  owner: ${OWNER}
  name: ${REPO}
  pullRequest:
    branch: .*
    commentControl: COMMENTS_ENABLED
filename: tools/cloudbuild/test.yaml
EOF
)

# github:
#   push:
#     branch: .*
#     OR
#     tag: .*
# includedFiles:
#  - .*
