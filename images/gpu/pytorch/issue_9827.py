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

"""Reproduction case for https://github.com/google/gvisor/issues/9827."""

import os
import time

import lightning as L
import psutil
import torch
from torch import nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from torchvision import models
from torchvision import transforms
from torchvision.datasets import CIFAR100

current_process = psutil.Process()
parent_process = current_process.parent()
print(f"Processes: {current_process=} {parent_process=}")


class NeuralNet(L.LightningModule):
  """NeuralNet is the neural network used in this test."""

  def __init__(self, nbr_cat):
    super().__init__()

    module = models.resnet50(weights=models.ResNet50_Weights.DEFAULT)
    module.fc = nn.Linear(2048, nbr_cat)

    self.module = module

  def forward(self, x):
    return self.module(x)

  def training_step(self, batch, batch_idx):
    x, y = batch
    y_hat = self(x)
    loss = F.cross_entropy(y_hat, y)
    return loss

  def configure_optimizers(self):
    return torch.optim.Adam(self.parameters(), lr=0.02)


def prepare_data():
  """prepare_data prepares the data to feed to the training pipeline."""
  pipeline = transforms.Compose([
      transforms.Resize((224, 224)),
      transforms.ToTensor(),
  ])

  train_ds = CIFAR100(os.environ["PYTORCH_DATASETS_DIR"],
                      train=True,
                      download=False,
                      transform=pipeline)
  train_dataloader = DataLoader(train_ds, batch_size=128, num_workers=4)

  val_ds = CIFAR100(os.environ["PYTORCH_DATASETS_DIR"],
                    train=False,
                    download=False,
                    transform=pipeline)
  val_dataloader = DataLoader(val_ds, batch_size=128, num_workers=4)

  return train_dataloader, val_dataloader


torch.set_float32_matmul_precision("medium")
train_dl, val_dl = prepare_data()
model = NeuralNet(100)
trainer = L.Trainer(max_epochs=1, strategy="ddp_notebook")

start = time.time()
# TODO(gvisor.dev/issue/9827): Make this not take forever.
trainer.fit(model, train_dl, val_dl)
time.sleep(20)
end = time.time()

training_duration = end - start

print(f"Training duration (seconds): {training_duration}")
