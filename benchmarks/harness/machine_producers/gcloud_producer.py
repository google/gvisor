# python3
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""A machine producer which produces machine objects using `gcloud`.

Machine producers produce valid harness.Machine objects which are backed by
real machines. This producer produces those machines on the given user's GCP
account using the `gcloud` tool.

GCloudProducer creates instances on the given GCP account named like:
`machine-XXXXXXX-XXXX-XXXX-XXXXXXXXXXXX` in a randomized fashion such that name
collisions with user instances shouldn't happen.

  Typical usage example:

  producer = GCloudProducer(args)
  machines = producer.get_machines(NUM_MACHINES)
  # run stuff on machines with machines[i].run(CMD)
  producer.release_machines(NUM_MACHINES)
"""
import datetime
import json
import subprocess
import threading
from typing import List, Dict, Any
import uuid

from benchmarks.harness import machine
from benchmarks.harness.machine_producers import gcloud_mock_recorder
from benchmarks.harness.machine_producers import machine_producer


class GCloudProducer(machine_producer.MachineProducer):
  """Implementation of MachineProducer backed by GCP.

  Produces Machine objects backed by GCP instances.

  Attributes:
    project: The GCP project name under which to create the machines.
    ssh_key_file: path to a valid ssh private key. See README on vaild ssh keys.
    image: image name as a string.
    image_project: image project as a string.
    machine_type: type of GCP to create. e.g. n1-standard-4
    zone: string to a valid GCP zone.
    ssh_user: string of user name for ssh_key
    ssh_password: string of password for ssh key
    mock: a mock printer which will print mock data if required. Mock data is
      recorded output from subprocess calls (returncode, stdout, args).
    condition: mutex for this class around machine creation and deleteion.
  """

  def __init__(self,
               project: str,
               ssh_key_file: str,
               image: str,
               image_project: str,
               machine_type: str,
               zone: str,
               ssh_user: str,
               ssh_password: str,
               mock: gcloud_mock_recorder.MockPrinter = None):
    self.project = project
    self.ssh_key_file = ssh_key_file
    self.image = image
    self.image_project = image_project
    self.machine_type = machine_type
    self.zone = zone
    self.ssh_user = ssh_user
    self.ssh_password = ssh_password
    self.mock = mock
    self.condition = threading.Condition()

  def get_machines(self, num_machines: int) -> List[machine.Machine]:
    """Returns requested number of machines backed by GCP instances."""
    if num_machines <= 0:
      raise ValueError(
          "Cannot ask for {num} machines!".format(num=num_machines))
    with self.condition:
      names = self._get_unique_names(num_machines)
      self._build_instances(names)
    instances = self._start_command(names)
    self._add_ssh_key_to_instances(names)
    return self._machines_from_instances(instances)

  def release_machines(self, machine_list: List[machine.Machine]):
    """Releases the requested number of machines, deleting the instances."""
    if not machine_list:
      return
    cmd = "gcloud compute instances delete --quiet".split(" ")
    names = [str(m) for m in machine_list]
    cmd.extend(names)
    cmd.append("--zone={zone}".format(zone=self.zone))
    self._run_command(cmd, detach=True)

  def _machines_from_instances(
      self, instances: List[Dict[str, Any]]) -> List[machine.Machine]:
    """Creates Machine Objects from json data describing created instances."""
    machines = []
    for instance in instances:
      name = instance["name"]
      kwargs = {
          "hostname":
              instance["networkInterfaces"][0]["accessConfigs"][0]["natIP"],
          "key_path":
              self.ssh_key_file,
          "username":
              self.ssh_user,
          "key_password":
              self.ssh_password
      }
      machines.append(machine.RemoteMachine(name=name, **kwargs))
    return machines

  def _get_unique_names(self, num_names) -> List[str]:
    """Returns num_names unique names based on data from the GCP project."""
    curr_machines = self._list_machines()
    curr_names = set([machine["name"] for machine in curr_machines])
    ret = []
    while len(ret) < num_names:
      new_name = "machine-" + str(uuid.uuid4())
      if new_name not in curr_names:
        ret.append(new_name)
        curr_names.update(new_name)
    return ret

  def _build_instances(self, names: List[str]) -> List[Dict[str, Any]]:
    """Creates instances using gcloud command.

    Runs the command `gcloud compute instances create` and returns json data
    on created instances on success. Creates len(names) instances, one for each
    name.

    Args:
      names: list of names of instances to create.

    Returns:
      List of json data describing created machines.
    """
    if not names:
      raise ValueError(
          "_build_instances cannot create instances without names.")
    cmd = "gcloud compute instances create".split(" ")
    cmd.extend(names)
    cmd.extend(
        "--preemptible --image={image} --zone={zone} --machine-type={machine_type}"
        .format(
            image=self.image, zone=self.zone,
            machine_type=self.machine_type).split(" "))
    if self.image_project:
      cmd.append("--image-project={project}".format(project=self.image_project))
    res = self._run_command(cmd)
    return json.loads(res.stdout)

  def _start_command(self, names):
    """Starts instances using gcloud command.

    Runs the command `gcloud compute instances start` on list of instances by
    name and returns json data on started instances on success.

    Args:
      names: list of names of instances to start.

    Returns:
      List of json data describing started machines.
    """
    if not names:
      raise ValueError("_start_command cannot start empty instance list.")
    cmd = "gcloud compute instances start".split(" ")
    cmd.extend(names)
    cmd.append("--zone={zone}".format(zone=self.zone))
    cmd.append("--project={project}".format(project=self.project))
    res = self._run_command(cmd)
    return json.loads(res.stdout)

  def _add_ssh_key_to_instances(self, names: List[str]) -> None:
    """Adds ssh key to instances by calling gcloud ssh command.

    Runs the command `gcloud compute ssh instance_name` on list of images by
    name. Tries to ssh into given instance

    Args:
      names: list of machine names to which to add the ssh-key
        self.ssh_key_file.

    Raises:
      subprocess.CalledProcessError: when underlying subprocess call returns an
      error other than 255 (Connection closed by remote host).
      TimeoutError: when 3 unsuccessful tries to ssh into the host return 255.
    """
    for name in names:
      cmd = "gcloud compute ssh {name}".format(name=name).split(" ")
      cmd.append("--ssh-key-file={key}".format(key=self.ssh_key_file))
      cmd.append("--zone={zone}".format(zone=self.zone))
      cmd.append("--command=uname")
      timeout = datetime.timedelta(seconds=5 * 60)
      start = datetime.datetime.now()
      while datetime.datetime.now() <= timeout + start:
        try:
          self._run_command(cmd)
          break
        except subprocess.CalledProcessError as e:
          if datetime.datetime.now() > timeout + start:
            raise TimeoutError(
                "Could not SSH into instance after 5 min: {name}".format(
                    name=name))
          # 255 is the returncode for ssh connection refused.
          elif e.returncode == 255:

            continue
          else:
            raise e

  def _list_machines(self) -> List[Dict[str, Any]]:
    """Runs `list` gcloud command and returns list of Machine data."""
    cmd = "gcloud compute instances list --project {project}".format(
        project=self.project).split(" ")
    res = self._run_command(cmd)
    return json.loads(res.stdout)

  def _run_command(self,
                   cmd: List[str],
                   detach: bool = False) -> [None, subprocess.CompletedProcess]:
    """Runs command as a subprocess.

    Runs command as subprocess and returns the result.
    If this has a mock recorder, use the record method to record the subprocess
    call.

    Args:
      cmd: command to be run as a list of strings.
      detach: if True, run the child process and don't wait for it to return.

    Returns:
      Completed process object to be parsed by caller or None if detach=True.

    Raises:
      CalledProcessError: if subprocess.run returns an error.
    """
    cmd = cmd + ["--format=json"]
    if detach:
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      if self.mock:
        out, _ = p.communicate()
        self.mock.record(
            subprocess.CompletedProcess(
                returncode=p.returncode, stdout=out, args=p.args))
      return

    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if self.mock:
      self.mock.record(res)
    if res.returncode != 0:
      raise subprocess.CalledProcessError(
          cmd=res.args,
          output=res.stdout,
          stderr=res.stderr,
          returncode=res.returncode)
    return res
