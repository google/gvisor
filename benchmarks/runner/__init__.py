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
"""High-level benchmark utility."""

import copy
import csv
import logging
import pkgutil
import pydoc
import re
import sys
import types
from typing import List
from typing import Tuple

import click

from benchmarks import suites
from benchmarks.harness import benchmark_driver
from benchmarks.harness.machine_producers import mock_producer
from benchmarks.harness.machine_producers import yaml_producer


@click.group()
@click.option(
    "--verbose/--no-verbose", default=False, help="Enable verbose logging.")
@click.option("--debug/--no-debug", default=False, help="Enable debug logging.")
def runner(verbose: bool = False, debug: bool = False):
  """Run distributed benchmarks.

  See the run and list commands for details.

  Args:
    verbose: Enable verbose logging.
    debug: Enable debug logging (supercedes verbose).
  """
  if debug:
    logging.basicConfig(level=logging.DEBUG)
  elif verbose:
    logging.basicConfig(level=logging.INFO)


def find_benchmarks(
    regex: str) -> List[Tuple[str, types.ModuleType, types.FunctionType]]:
  """Finds all available benchmarks.

  Args:
    regex: A regular expression to match.

  Returns:
    A (short_name, module, function) tuple for each match.
  """
  pkgs = pkgutil.walk_packages(suites.__path__, suites.__name__ + ".")
  found = []
  for _, name, _ in pkgs:
    mod = pydoc.locate(name)
    funcs = [
        getattr(mod, x)
        for x in dir(mod)
        if suites.is_benchmark(getattr(mod, x))
    ]
    for func in funcs:
      # Use the short_name with the benchmarks. prefix stripped.
      prefix_len = len(suites.__name__ + ".")
      short_name = mod.__name__[prefix_len:] + "." + func.__name__
      # Add to the list if a pattern is provided.
      if re.compile(regex).match(short_name):
        found.append((short_name, mod, func))
  return found


@runner.command("list")
@click.argument("method", nargs=-1)
def list_all(method):
  """Lists available benchmarks."""
  if not method:
    method = ".*"
  else:
    method = "(" + ",".join(method) + ")"
  for (short_name, _, func) in find_benchmarks(method):
    print("Benchmark %s:" % short_name)
    metrics = suites.benchmark_metrics(func)
    if func.__doc__:
      print("    " + func.__doc__.lstrip().rstrip())
    if metrics:
      print("\n    Metrics:")
    for metric in metrics:
      print("\t{name}: {doc}".format(name=metric[0], doc=metric[1]))
    print("\n")


# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
@runner.command(
    context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.pass_context
@click.argument("method")
@click.option("--mock/--no-mock", default=False, help="Mock the machines.")
@click.option("--env", default=None, help="Specify a yaml file with machines.")
@click.option(
    "--runtime", default=["runc"], help="The runtime to use.", multiple=True)
@click.option("--metric", help="The metric to extract.", multiple=True)
@click.option(
    "--runs", default=1, help="The number of times to run each benchmark.")
@click.option(
    "--stat",
    default="median",
    help="How to aggregate the data from all runs."
    "\nmedian - returns the median of all runs (default)"
    "\nall - returns all results comma separated"
    "\nmeanstd - returns result as mean,std")
# pylint: disable=too-many-statements
def run(ctx, method: str, runs: int, env: str, mock: bool, runtime: List[str],
        metric: List[str], stat: str, **kwargs):
  """Runs arbitrary benchmarks.

  All unknown command line flags are passed through to the underlying benchmark
  method. Flags may be specified multiple times, in which case it is considered
  a "dimension" for the test, and a comma-separated table will be emitted
  instead of a single result.

  See the output of list to see available metrics for any given benchmark
  method. The method parameter is a regular expression that will match against
  available benchmarks. If multiple benchmarks match, then that is considered a
  distinct "dimension" for the test.

  All benchmarks are run in parallel where possible, but have exclusive
  ownership over the individual machines.

  Exactly one of the --mock and --env flag must be specified.

  Every benchmark method will be run the times indicated by --runs.

  Args:
    ctx: Click context.
    method: A regular expression for methods to be run.
    runs: Number of runs.
    env: Environment to use.
    mock: If true, use mocked environment (supercedes env).
    runtime: A list of runtimes to test.
    metric: A list of metrics to extract.
    stat: The class of statistics to extract.
    **kwargs: Dimensions to test.
  """
  # First, calculate additional arguments.
  #
  # This essentially calculates any arguments that appear multiple times, and
  # moves those to the "dimensions" dictionary, which maps to lists. These
  # dimensions are then iterated over to generate the relevant csv output.
  dimensions = {}

  if stat not in ["median", "all", "meanstd"]:
    raise ValueError("Illegal value for --result, see help.")

  def squish(key: str, value: str):
    """Collapse an argument into kwargs or dimensions."""
    if key in dimensions:
      # Extend an existing dimension.
      dimensions[key].append(value)
    elif key in kwargs:
      # Create a new dimension.
      dimensions[key] = [kwargs[key], value]
      del kwargs[key]
    else:
      # A single value.
      kwargs[key] = value

  for item in ctx.args:
    if "=" in method:
      # This must be the method. The method is simply set to the first
      # non-matching argument, which we're also parsing here.
      item, method = method, item
    if "=" not in item:
      logging.error("illegal argument: %s", item)
      sys.exit(1)
    (key, value) = item.lstrip("-").split("=", 1)
    squish(key, value)

  # Convert runtime and metric to dimensions.
  #
  # They exist only in the arguments above for documentation purposes.
  # Essentially here we are treating them like anything else. Note however,
  # that an empty set here will result in a dimension. This is important for
  # metrics, where an empty set actually means all metrics.
  def fold(key: str, value, allow_flatten=False):
    """Collapse a list value into kwargs or dimensions."""
    if len(value) == 1 and allow_flatten:
      kwargs[key] = value[0]
    else:
      dimensions[key] = value

  fold("runtime", runtime, allow_flatten=True)
  fold("metric", metric)

  # Lookup the methods.
  #
  # We match the method parameter to a regular expression. This allows you to
  # do things like `run --mock .*` for a broad test. Note that we track the
  # short_names in the dimensions here, and look up again in the recursion.
  methods = {
      short_name: func for (short_name, _, func) in find_benchmarks(method)
  }
  if not methods:
    # Must match at least one method.
    logging.error("no matching benchmarks for %s: try list.", method)
    sys.exit(1)
  fold("method", list(methods.keys()), allow_flatten=True)

  # Construct the environment.
  if mock and env:
    # You can't provide both.
    logging.error("both --mock and --env are set: which one is it?")
    sys.exit(1)
  elif mock:
    producer = mock_producer.MockMachineProducer()
  elif env:
    producer = yaml_producer.YamlMachineProducer(env)
  else:
    # You must provide one of mock or env.
    logging.error("no enviroment provided: use --mock or --env.")
    sys.exit(1)

  # Spin up the drivers.
  #
  # We ensure that metric is the last entry, because we have special behavior.
  # They actually run the test once and the benchmark is a generator that
  # produces all viable metrics.
  dimension_keys = list(dimensions.keys())
  if "metric" in dimension_keys:
    dimension_keys.remove("metric")
    dimension_keys.append("metric")
  drivers = []

  def _start(keywords, finished, left):
    """Runs a test across dimensions recursively."""
    # Resolve the method fully, it starts as a string.
    if "method" in keywords and isinstance(keywords["method"], str):
      keywords["method"] = methods[keywords["method"]]
    # Is this a non-recursive case?
    if not left:
      driver = benchmark_driver.BenchmarkDriver(producer, runs=runs, **keywords)
      driver.start()
      drivers.append((finished, driver))
    else:
      # Recurse on the next dimension.
      current, left = left[0], left[1:]
      keywords = copy.deepcopy(keywords)
      if current == "metric":
        # We use a generator, popped below. Note that metric is
        # guaranteed to be the last element here, and we will provide
        # the value for 'done' below when generating the csv.
        keywords[current] = dimensions[current]
        _start(keywords, finished, left)
      else:
        # Generate manually.
        for value in dimensions[current]:
          keywords[current] = value
          _start(keywords, finished + [value], left)

  # Start all the drivers, recursively.
  _start(kwargs, [], dimension_keys)

  # Finish all tests, write results.
  output = csv.writer(sys.stdout)
  output.writerow(dimension_keys + ["result"])
  for (done, driver) in drivers:
    driver.join()
    for (metric_name, result) in getattr(driver, stat)():
      output.writerow([  # Collapse the method name.
          hasattr(x, "__name__") and x.__name__ or x for x in done
      ] + [metric_name] + result)


@runner.command()
@click.argument("env")
@click.option(
    "--cmd", default="uname -a", help="command to run on all found machines")
@click.option(
    "--workload", default="true", help="workload to run all found machines")
def validate(env, cmd, workload):
  """Validates an environment described by yaml file."""
  producer = yaml_producer.YamlMachineProducer(env)
  for machine in producer.machines:
    print("Machine %s:" % machine)
    stdout, _ = machine.run(cmd)
    print("  Output of '%s': %s" % (cmd, stdout.lstrip().rstrip()))
    image = machine.pull(workload)
    stdout = machine.container(image).run()
    print("  Container %s: %s" % (workload, stdout.lstrip().rstrip()))
