# Copyright 2023 The gVisor Authors.
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

"""Download PyTorch datasets used in tests."""

import os

from torchvision import datasets
from torchvision import models

datasets_dir = os.environ["PYTORCH_DATASETS_DIR"]
for dataset in (
    datasets.MNIST,
    datasets.CIFAR100,
):
  dataset(datasets_dir, train=True, download=True)
  dataset(datasets_dir, train=False, download=True)

# Download resnet50 weights to TORCH_HOME:
models.resnet50(weights=models.ResNet50_Weights.DEFAULT)
