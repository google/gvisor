# Application Compatibility Tests

This directory contains compatibility tests used to automate the process of
determining third-party application compatibility with gVisor over time.

To reduce iteration time, these tests are *not* a part of our CI/CD pipeline.

## Application versions

The images used for each stack are in `images/compatibility/<application>`.
The application version under test is determined by the Dockerfile present in
these directories.

## Running

First load the required images (built from `images/compatibility/...`):

```
make load-compatibility_gitea
# or load every image at once. this can take a while:
make load-compatibility
```

Then run the native baseline and the gVisor target. The Docker daemon must be
running locally, and gVisor must be present as the `runsc` runtime:

```
make test TARGETS="//test/compatibility:gitea_native //test/compatibility:gitea_runsc"
```

## Website

Soon the results from these tests will be listed on [gvisor.dev](https://gvisor.dev).