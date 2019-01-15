#!/bin/bash

# Sample script to install runsc

wget -q --https-only \
    https://storage.googleapis.com/gvisor/releases/nightly/${RUNSC_VERSION}/runsc
chmod +x runsc
sudo mv runsc /usr/local/bin/
