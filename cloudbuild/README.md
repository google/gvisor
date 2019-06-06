# Cloud Build configuration

This directory contains [Google Cloud Build][cloud-build] configuration files.
The project maintains manage presubmit, continuous integration and release
pipelines based on these files.

# Presubmits

Many of the workflows described below can be used as presubmit checks. In
relevant configuration files, the incoming branch is validated to take the
appropriate presubmit or postsubmit actions.

In order to connect a Cloud Build trigger with a [GitHub check][github], a
custom [Google Cloud Function][cloud-functions] may be used within the same
project as the Cloud Build trigger. Unfortunately, the standard Cloud Build
application allows only a single project to be associated with a repository;
supporting a check with a cloud function allows any number of presubmit checks
to be added.

To add a presubmit check to a presubmit project, follow the instructions in the
`check` directory. The standard GitHub branch protection settings, or other
mechanism, can be used to ensure that the presubmit check blocks submission.

## Go validation

The `go.yaml` file contains build instructions that will automatically maintain
a synthetic `go` branch. This branch works with `go get` and `go modules`.

## Simple tests

All simple tests can be executed with the `test.yaml` file. Simple tests are
those that can be executed in any environment, directly from bazel.

## Complex tests

Complex tests can be executed with the `script.yaml` file. This file will bring
up a [Google Compute Engine][compute-engine] instance that has been configured
with `tools/image_setup.sh`, has nested virtualization enabled, and use
`tools/image_execute.sh` to remotely execute the given script.

Different workflows may be defined with e.g. `tests/docker_tests.sh` as the
`_SCRIPT` target. These workflows can each use a different project, and may
provide their own check.

# Postsubmits

Many of the workflows can be used as a postsubmit workflow. This means that
they will trigger on a successful merge. Configurations that support this will
check for the `master` branch before taking relevant action.

These workflows support a build badge. To add a build badge, follow the
instructions in the `badge` directory.

## Go branch generation

The `go.yaml` file can be used as a postsubmit hook to maintain the `go`
branch. The `_ORIGIN` substitution must be a repository that is mirrored to
GitHub, or GitHub itself.

## Continuous builds

The `build.yaml` file can be used to build all available targets continously,
without executing any tests.

This is ideal target to use for a generic build badge, since it avoids flaky
tests and generally corresponds to actual build breakages.

## Releases

The release pipeline should be configured to use the `release.yaml` file. The
bucket may be configured by the `_BUCKET` substitution.

For nightly releases `_DATE` should be true, for continuous releases `_LATEST`
should be true, and for tagged releases, `_TAG` should be true. These different
configurations can use different triggers.

[cloud-build]: https://cloud.google.com/cloud-build/
[compute-engine]: https://cloud.google.com/compute/
[github]: https://developer.github.com/v3/checks/
[cloud-functions]: https://cloud.google.com/functions/
