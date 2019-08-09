#!/bin/bash

# Copyright 2019 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script creates an ext4 image with $1 depth of directories and a file in
# the inner most directory. The created file is at path /1/2/.../depth/file.txt.
# The ext4 image is written to $2. The image is temporarily mounted at
# /tmp/mountpoint. This script must be run with sudo privileges.

# Usage:
# sudo bash make_deep_ext4.sh {depth} {output path}

# Check positional arguments.
if [ "$#" -ne 2 ]; then
    echo "Usage: sudo bash make_deep_ext4.sh {depth} {output path}"
    exit 1
fi

# Make sure depth is a non-negative number.
if ! [[ "$1" =~ ^[0-9]+$ ]]; then
        echo "Depth must be a non-negative number."
        exit 1
fi

# Create a 1 MB filesystem image at the requested output path.
rm -f $2
fallocate -l 1M $2
if [ $? -ne 0 ]; then
    echo "fallocate failed"
    exit $?
fi

# Convert that blank into an ext4 image.
mkfs.ext4 -j $2
if [ $? -ne 0 ]; then
    echo "mkfs.ext4 failed"
    exit $?
fi

# Mount the image.
MOUNTPOINT=/tmp/mountpoint
mkdir -p $MOUNTPOINT
mount -o loop $2 $MOUNTPOINT
if [ $? -ne 0 ]; then
    echo "mount failed"
    exit $?
fi

# Create nested directories and the file.
if [ "$1" -eq 0 ]; then
   FILEPATH=$MOUNTPOINT/file.txt
else
   FILEPATH=$MOUNTPOINT/$(seq -s '/' 1 $1)/file.txt
fi
mkdir -p $(dirname $FILEPATH) || exit
touch $FILEPATH

# Clean up.
umount $MOUNTPOINT
rm -rf $MOUNTPOINT
