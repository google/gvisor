# python3
# Copyright 2019 The gVisor Authors.
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
"""Module with the guts of `click` commands.

Overrides of the click.core.Command. This is done so flags are inherited between
similar commands (the run command). The classes below are meant to be used in
click templates like so.

@runner.command("run-mock", RunCommand)
def run_mock(**kwargs):
  # mock implementation

"""
import os

import click


class RunCommand(click.core.Command):
  """Base Run Command with flags.

  Attributes:
    method: regex of which suite to choose (e.g. sysbench would run
      sysbench.cpu, sysbench.memory, and sysbench.mutex) See list command for
      details.
    metric: metric(s) to extract. See list command for details.
    runtime: the runtime(s) on which to run.
    runs: the number of runs to do of each method.
    stat: how to compile results in the case of multiple run (e.g. median).
  """

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    method = click.core.Argument(("method",))

    metric = click.core.Option(("--metric",),
                               help="The metric to extract.",
                               multiple=True)

    runtime = click.core.Option(("--runtime",),
                                default=["runc"],
                                help="The runtime to use.",
                                multiple=True)
    runs = click.core.Option(("--runs",),
                             default=1,
                             help="The number of times to run each benchmark.")
    stat = click.core.Option(
        ("--stat",),
        default="median",
        help="How to aggregate the data from all runs."
        "\nmedian - returns the median of all runs (default)"
        "\nall - returns all results comma separated"
        "\nmeanstd - returns result as mean,std")
    self.params.extend([method, runtime, runs, stat, metric])
    self.ignore_unknown_options = True
    self.allow_extra_args = True


class LocalCommand(RunCommand):
  """LocalCommand inherits all flags from RunCommand.

  Attributes:
    limit: limits the number of machines on which to run benchmarks. This limits
      for local how many benchmarks may run at a time. e.g. "startup" requires
      one machine -- passing two machines would limit two startup jobs at a
      time. Default is infinity.
  """

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.params.append(
        click.core.Option(
            ("--limit",),
            default=1,
            help="Limit of number of benchmarks that can run at a given time."))


class GCPCommand(RunCommand):
  """GCPCommand inherits all flags from RunCommand and adds flags for run_gcp method.

  Attributes:
    image_file: name of the image to build machines from
    zone_file: a GCP zone (e.g. us-west1-b)
    installers: named installers for post-create
    machine_type: type of machine to create (e.g. n1-standard-4)
  """

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)

    image_file = click.core.Option(
        ("--image_file",),
        help="The binary that emits the GCP image.",
        default=os.path.join(
            os.path.dirname(__file__), "../../tools/vm/ubuntu1604"),
    )
    zone_file = click.core.Option(
        ("--zone_file",),
        help="The binary that emits the GCP zone.",
        default=os.path.join(os.path.dirname(__file__), "../../tools/vm/zone"),
    )
    internal = click.core.Option(
        ("--internal/--no-internal",),
        help="""Use instance internal IPs. Used if bm-tools runner is running on
        GCP instance with firewall rules blocking external IPs.""",
        default=False,
    )
    installers = click.core.Option(
        ("--installers",),
        help="The set of installers to use.",
        multiple=True,
    )
    machine_type = click.core.Option(
        ("--machine_type",),
        help="Type to make all machines.",
        default="n1-standard-4",
    )
    self.params.extend([
        image_file,
        zone_file,
        internal,
        machine_type,
        installers,
    ])
