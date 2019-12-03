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
"""Core benchmark annotations."""

import functools
import inspect
import types
from typing import List
from typing import Tuple

BENCHMARK_METRICS = '__benchmark_metrics__'
BENCHMARK_MACHINES = '__benchmark_machines__'


def is_benchmark(func: types.FunctionType) -> bool:
  """Returns true if the given function is a benchmark."""
  return isinstance(func, types.FunctionType) and \
      hasattr(func, BENCHMARK_METRICS) and \
      hasattr(func, BENCHMARK_MACHINES)


def benchmark_metrics(func: types.FunctionType) -> List[Tuple[str, str]]:
  """Returns the list of available metrics."""
  return [(metric.__name__, metric.__doc__)
          for metric in getattr(func, BENCHMARK_METRICS)]


def benchmark_machines(func: types.FunctionType) -> int:
  """Returns the number of machines required."""
  return getattr(func, BENCHMARK_MACHINES)


# pylint: disable=unused-argument
def default(value, **kwargs):
  """Returns the passed value."""
  return value


def benchmark(metrics: List[types.FunctionType] = None,
              machines: int = 1) -> types.FunctionType:
  """Define a benchmark function with metrics.

  Args:
    metrics: A list of metric functions.
    machines: The number of machines required.

  Returns:
    A function that accepts the given number of machines, and iteratively
    returns a set of (metric_name, metric_value) pairs when called repeatedly.
  """
  if not metrics:
    # The default passes through.
    metrics = [default]

  def decorator(func: types.FunctionType) -> types.FunctionType:
    """Decorator function."""
    # Every benchmark should accept at least two parameters:
    #   runtime: The runtime to use for the benchmark (str, required).
    #   metrics: The metrics to use, if not the default (str, optional).
    @functools.wraps(func)
    def wrapper(*args, runtime: str, metric: list = None, **kwargs):
      """Wrapper function."""
      # First -- ensure that we marshall all types appropriately. In
      # general, we will call this with only strings. These strings will
      # need to be converted to their underlying types/classes.
      sig = inspect.signature(func)
      for param in sig.parameters.values():
        if param.annotation != inspect.Parameter.empty and \
           param.name in kwargs and not isinstance(kwargs[param.name], param.annotation):
          try:
            # Marshall to the appropriate type.
            kwargs[param.name] = param.annotation(kwargs[param.name])
          except Exception as exc:
            raise ValueError(
                'illegal type for %s(%s=%s): %s' %
                (func.__name__, param.name, kwargs[param.name], exc))
        elif param.default != inspect.Parameter.empty and \
             param.name not in kwargs:
          # Ensure that we have the value set, because it will
          # be passed to the metric function for evaluation.
          kwargs[param.name] = param.default

      # Next, figure out how to apply a metric. We do this prior to
      # running the underlying function to prevent having to wait a few
      # minutes for a result just to see some error.
      if not metric:
        # Return all metrics in the iterator.
        result = func(*args, runtime=runtime, **kwargs)
        for metric_func in metrics:
          yield (metric_func.__name__, metric_func(result, **kwargs))
      else:
        result = None
        for single_metric in metric:
          for metric_func in metrics:
            # Is this a function that matches the name?
            # Apply this function to the result.
            if metric_func.__name__ == single_metric:
              if not result:
                # Lazy evaluation: only if metric matches.
                result = func(*args, runtime=runtime, **kwargs)
              yield single_metric, metric_func(result, **kwargs)

    # Set metadata on the benchmark (used above).
    setattr(wrapper, BENCHMARK_METRICS, metrics)
    setattr(wrapper, BENCHMARK_MACHINES, machines)
    return wrapper

  return decorator
