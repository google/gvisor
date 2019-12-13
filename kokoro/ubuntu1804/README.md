# Updating Kokoro VM images

After making changes to files in this directory, you must run the following
commands to update the image Kokoro uses:

```shell
gcloud config set project gvisor-kokoro-testing
third_party/gvisor/kokoro/ubuntu1804/build.sh
```

Note: the command above will change your default project for `gcloud`. Run
`gcloud config set project` again to revert back to your default project.

After the script finishes, the last few lines of the output will container the
image name. If the output was lost, you can run `build.sh` again to print the
image name.

```
NAME                    PROJECT                FAMILY  DEPRECATED  STATUS
image-6777fa4666a968c8  gvisor-kokoro-testing                      READY
+ cleanup
+ gcloud compute instances delete --quiet build-tlfrdv
Deleted [https://www.googleapis.com/compute/v1/projects/gvisor-kokoro-testing/zones/us-central1-f/instances/build-tlfrdv].
```

To setup Kokoro to use the new image, copy the image names to their
corresponding file below:

*   //devtools/kokoro/config/gcp/gvisor/ubuntu1804.gcl
