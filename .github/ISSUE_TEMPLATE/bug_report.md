---
name: Bug report
about: Create a bug report to help us improve
title:
labels: 'type: bug'
assignees: ''
---

**Description**

A clear description of what the bug is. If possible, explicitly indicate the
expected behavior vs. the observed behavior.

**Steps to reproduce**

If available, please include detailed reproduction steps.

If the bug requires software that is not publicly available, see if it can be
reproduced with software that is publicly available.

**Environment**

Please include the following details of your environment:

*   `runsc -version`
*   `docker version` or `docker info` (if available)
*   `kubectl version` and `kubectl get nodes` (if using Kubernetes)
*   `uname -a`
*   `git describe` (if built from source)
*   `runsc` debug logs (if available)
