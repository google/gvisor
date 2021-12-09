// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ml

import (
	"context"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// BenchmarkTensorflow runs workloads from a TensorFlow tutorial.
// See: https://github.com/aymericdamien/TensorFlow-Examples
func BenchmarkTensorflow(b *testing.B) {
	workloads := map[string]string{
		"GradientDecisionTree": "2_BasicModels/gradient_boosted_decision_tree.py",
		"Kmeans":               "2_BasicModels/kmeans.py",
		"LogisticRegression":   "2_BasicModels/logistic_regression.py",
		"NearestNeighbor":      "2_BasicModels/nearest_neighbor.py",
		"RandomForest":         "2_BasicModels/random_forest.py",
		"ConvolutionalNetwork": "3_NeuralNetworks/convolutional_network.py",
		"MultilayerPerceptron": "3_NeuralNetworks/multilayer_perceptron.py",
		"NeuralNetwork":        "3_NeuralNetworks/neural_network.py",
	}

	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	for name, workload := range workloads {
		runName, err := tools.ParametersToName(tools.Parameter{
			Name:  "operation",
			Value: name,
		})
		if err != nil {
			b.Fatalf("Failed to parse param: %v", err)
		}

		b.Run(runName, func(b *testing.B) {
			ctx := context.Background()

			b.ResetTimer()
			b.StopTimer()

			for i := 0; i < b.N; i++ {
				container := machine.GetContainer(ctx, b)
				defer container.CleanUp(ctx)
				if err := harness.DropCaches(machine); err != nil {
					b.Skipf("failed to drop caches: %v. You probably need root.", err)
				}

				// Run tensorflow.
				b.StartTimer()
				if out, err := container.Run(ctx, dockerutil.RunOpts{
					Image:   "benchmarks/tensorflow",
					Env:     []string{"PYTHONPATH=$PYTHONPATH:/TensorFlow-Examples/examples"},
					WorkDir: "/TensorFlow-Examples/examples",
				}, "python", workload); err != nil {
					b.Errorf("failed to run container: %v logs: %s", err, out)
				}
				b.StopTimer()
			}
		})
	}
}

func TestMain(m *testing.M) {
	harness.Init()
	harness.SetFixedBenchmarks()
	os.Exit(m.Run())
}
