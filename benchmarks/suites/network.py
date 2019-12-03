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
"""Network microbenchmarks."""

from typing import Dict

from benchmarks import suites
from benchmarks.harness import machine
from benchmarks.suites import helpers
from benchmarks.workloads import iperf


def run_iperf(client: machine.Machine,
              server: machine.Machine,
              client_kwargs: Dict[str, str] = None,
              server_kwargs: Dict[str, str] = None) -> str:
  """Measure iperf performance.

  Args:
    client: A machine object.
    server: A machine object.
    client_kwargs: Additional client container options.
    server_kwargs: Additional server container options.

  Returns:
    The output of iperf.
  """
  if not client_kwargs:
    client_kwargs = dict()
  if not server_kwargs:
    server_kwargs = dict()

  # Pull images.
  netcat = client.pull("netcat")
  iperf_client_image = client.pull("iperf")
  iperf_server_image = server.pull("iperf")

  # Set this due to a bug in the kernel that resets connections.
  client.run("sudo /sbin/sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1")
  server.run("sudo /sbin/sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1")

  with server.container(
      iperf_server_image, port=5001, **server_kwargs).detach() as iperf_server:
    (host, port) = iperf_server.address()
    # Wait until the service is available.
    client.container(netcat).run(host=host, port=port)
    # Run a warm-up run.
    client.container(
        iperf_client_image, stderr=True, **client_kwargs).run(
            host=host, port=port)
    # Run the client with relevant arguments.
    res = client.container(iperf_client_image, stderr=True, **client_kwargs)\
        .run(host=host, port=port)
    helpers.drop_caches(client)
    return res


@suites.benchmark(metrics=[iperf.bandwidth], machines=2)
def upload(client: machine.Machine, server: machine.Machine, **kwargs) -> str:
  """Measure upload performance.

  Args:
    client: A machine object.
    server: A machine object.
    **kwargs: Client container options.

  Returns:
    The output of iperf.
  """
  if kwargs["runtime"] == "runc":
    kwargs["network_mode"] = "host"
  return run_iperf(client, server, client_kwargs=kwargs)


@suites.benchmark(metrics=[iperf.bandwidth], machines=2)
def download(client: machine.Machine, server: machine.Machine, **kwargs) -> str:
  """Measure download performance.

  Args:
    client: A machine object.
    server: A machine object.
    **kwargs: Server container options.

  Returns:
    The output of iperf.
  """

  client_kwargs = {"network_mode": "host"}
  return run_iperf(
      client, server, client_kwargs=client_kwargs, server_kwargs=kwargs)
