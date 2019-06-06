# Checks

Checks can be dynamically deployed to the any project running builds for
presubmits. Each presubmit should be deployed in a separate project, which
minimizes the shared permissions and scopes required. The check will notify for
all build triggers in the project.

A GitHub token with `repo:status` scope must be used for `TOKEN`.

To deploy, use the following command with your own variables:

```bash
TOKEN=XXX
CHECK=YYY
gcloud functions deploy                           \
    --runtime nodejs8                             \
    --trigger-resource cloud-builds               \
    --trigger-event google.pubsub.topic.publish   \
    --set-env-vars="TOKEN=${TOKEN},NAME=${CHECK}" \
    check
```
