# Triggers

Triggers is a simple cloud function that listens for GitHub webhook requests,
and kicks off relevant builds. The builds function in turn listens for build
event notifications (such as created, started, finished, etc.) and posts a check
status to GitHub in return.
