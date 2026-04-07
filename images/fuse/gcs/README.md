# GCSFUSE gVisor Compatibility Test

This directory contains a test suite for `gcsfuse` compatibility with gVisor.

To run the test, simply execute the `run_test.sh` script:

```bash
./images/fuse/gcs/run_test.sh
```

The script will:

1.  Check for gVisor (runsc) and gcloud credentials.
2.  Create a temporary GCS bucket.
3.  Build the test Docker image.
4.  Run the test container using gVisor.
5.  Clean up the temporary GCS bucket.

For more details on the manual steps, refer to the script's source code.
