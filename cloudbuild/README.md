# Cloud Build configuration

This directory contains [Google Cloud Build][cloud-build] configuration files.
The project maintains manage presubmit, continuous integration and release
pipelines based on these files. Note that these currently depend on alpha
features.

See `setup_presubmit.sh` and `setup_postsubmit.sh` for a self-documenting
description of the presubmit and post submit hooks.

## Go validation

The `go.yaml` file contains build instructions that will automatically maintain
substitution.

## Test scripts

Complex tests can be executed with the `script.yaml` file. This file will bring
up a [Google Compute Engine][compute-engine] instance that has been configured
with `tools/image_setup.sh`, has nested virtualization enabled, and use
`tools/image_execute.sh` to remotely execute the given script.

Different workflows may be defined with e.g. `tests/docker_tests.sh` as the
`_SCRIPT` target. These workflows can each use a different project, and may
provide their own check.

# Build badge

The `build.yaml` has a basic setup for producing build badges. This can be used
as a postsubmit hook, assuming an appropriate `_BUCKET` is provided.

## Releases

The release pipeline should be configured to use the `release.yaml` file. The
bucket may be configured by the `_BUCKET` substitution.

[cloud-build]: https://cloud.google.com/cloud-build/
