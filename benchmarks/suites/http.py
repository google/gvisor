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
"""HTTP benchmarks."""

from benchmarks import suites
from benchmarks.harness import machine
from benchmarks.workloads import ab


# pylint: disable=too-many-arguments
def http(server: machine.Machine,
         client: machine.Machine,
         workload: str,
         requests: int = 5000,
         connections: int = 10,
         port: int = 80,
         path: str = "notfound",
         **kwargs) -> str:
  """Run apachebench (ab) against an http server.

  Args:
    server: A machine object.
    client: A machine object.
    workload: The http-serving workload.
    requests: Number of requests to send the server. Default is 5000.
    connections: Number of concurent connections to use. Default is 10.
    port: The port to access in benchmarking.
    path: File to download, generally workload-specific.
    **kwargs: Additional container options.

  Returns:
    The full apachebench output.
  """
  # Pull the client & server.
  apachebench = client.pull("ab")
  netcat = client.pull("netcat")
  image = server.pull(workload)

  with server.container(image, port=port, **kwargs).detach() as container:
    (host, port) = container.address()
    # Wait for the server to come up.
    client.container(netcat).run(host=host, port=port)
    # Run the benchmark, no arguments.
    return client.container(apachebench).run(
        host=host,
        port=port,
        requests=requests,
        connections=connections,
        path=path)


# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
def http_app(server: machine.Machine,
             client: machine.Machine,
             workload: str,
             requests: int = 5000,
             connections: int = 10,
             port: int = 80,
             path: str = "notfound",
             **kwargs) -> str:
  """Run apachebench (ab) against an http application.

  Args:
    server: A machine object.
    client: A machine object.
    workload: The http-serving workload.
    requests: Number of requests to send the server. Default is 5000.
    connections: Number of concurent connections to use. Default is 10.
    port: The port to use for benchmarking.
    path: File to download, generally workload-specific.
    **kwargs: Additional container options.

  Returns:
    The full apachebench output.
  """
  # Pull the client & server.
  apachebench = client.pull("ab")
  netcat = client.pull("netcat")
  server_netcat = server.pull("netcat")
  redis = server.pull("redis")
  image = server.pull(workload)
  redis_port = 6379
  redis_name = "redis_server"

  with server.container(redis, name=redis_name).detach():
    server.container(server_netcat, links={redis_name: redis_name})\
        .run(host=redis_name, port=redis_port)
    with server.container(image, port=port, links={redis_name: redis_name}, **kwargs)\
            .detach(host=redis_name) as container:
      (host, port) = container.address()
      # Wait for the server to come up.
      client.container(netcat).run(host=host, port=port)
      # Run the benchmark, no arguments.
      return client.container(apachebench).run(
          host=host,
          port=port,
          requests=requests,
          connections=connections,
          path=path)


@suites.benchmark(metrics=[ab.transfer_rate, ab.latency], machines=2)
def httpd(*args, **kwargs) -> str:
  """Apache2 benchmark."""
  return http(*args, workload="httpd", port=80, **kwargs)


@suites.benchmark(
    metrics=[ab.transfer_rate, ab.latency, ab.requests_per_second], machines=2)
def nginx(*args, **kwargs) -> str:
  """Nginx benchmark."""
  return http(*args, workload="nginx", port=80, **kwargs)


@suites.benchmark(
    metrics=[ab.transfer_rate, ab.latency, ab.requests_per_second], machines=2)
def node(*args, **kwargs) -> str:
  """Node benchmark."""
  return http_app(*args, workload="node_template", path="", port=8080, **kwargs)


@suites.benchmark(
    metrics=[ab.transfer_rate, ab.latency, ab.requests_per_second], machines=2)
def ruby(*args, **kwargs) -> str:
  """Ruby benchmark."""
  return http_app(*args, workload="ruby_template", path="", port=9292, **kwargs)
