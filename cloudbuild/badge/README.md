# Badges

Badges can be dynamically updated based on build status. Each badge must be
deployed to a separate project, which will update based on any build. Badges
should only be deployed for continuous builds against submitted branches, not
for presubmits.

To deploy, use the following command with your own variables:

```bash
BUCKET=mybucket
SUCCESS=success.svg
FAILURE=failure.svg
BADGE=badge.svg
gcloud functions deploy                                                                    \
    --runtime nodejs8                                                                      \
    --trigger-resource cloud-builds                                                        \
    --trigger-event google.pubsub.topic.publish                                            \
    --set-env-vars="BUCKET=${BUCKET},SUCCESS=${SUCCESS},FAILURE=${FAILURE},BADGE=${BADGE}" \
    badge
```
