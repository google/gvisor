#!/bin/bash

# A sample script to validating the running containerd-shim-runsc-v1.

set -ex

ps aux | grep [c]ontainerd-shim-runsc-v1
