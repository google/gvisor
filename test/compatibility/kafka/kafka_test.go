// Copyright 2026 The gVisor Authors.
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

// Package kafka is a gVisor compatibility test for Apache Kafka (KRaft mode).
//
// The Kafka version under test is pinned in
// images/compatibility/kafka/kafka/Dockerfile.
package kafka

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/compatibility"
)

const (
	kafkaImage = "compatibility/kafka/kafka"

	bootstrap = "localhost:9092"
	binDir    = "/opt/kafka/bin/"
	topic     = "gv"
	want      = "gvisor-msg"

	readyTimeout = 3 * time.Minute
	pollInterval = 3 * time.Second
)

func TestKafka(t *testing.T) {
	ctx := context.Background()

	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	if err := c.Spawn(ctx, dockerutil.RunOpts{Image: kafkaImage}); err != nil {
		t.Fatalf("failed to start kafka: %v", err)
	}

	// run executes a shell command inside the container.
	run := func(cmd string) (string, error) {
		return c.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c", cmd)
	}

	// Wait for the broker to accept admin requests.
	compatibility.Poll(ctx, t, "kafka broker to be ready", readyTimeout, pollInterval, func() error {
		if out, err := run(binDir + "kafka-topics.sh --bootstrap-server " + bootstrap + " --list"); err != nil {
			return fmt.Errorf("kafka-topics --list: %v (%s)", err, out)
		}
		return nil
	})

	// Create a topic.
	if out, err := run(binDir + "kafka-topics.sh --bootstrap-server " + bootstrap +
		" --create --topic " + topic + " --partitions 1 --replication-factor 1"); err != nil {
		t.Fatalf("create topic: %v\n%s", err, out)
	}

	// Produce a single message.
	if out, err := run("echo " + want + " | " + binDir + "kafka-console-producer.sh --bootstrap-server " +
		bootstrap + " --topic " + topic); err != nil {
		t.Fatalf("produce: %v\n%s", err, out)
	}

	// Consume it back.
	out, err := run(binDir + "kafka-console-consumer.sh --bootstrap-server " + bootstrap +
		" --topic " + topic + " --from-beginning --max-messages 1 --timeout-ms 30000")
	if err != nil {
		t.Fatalf("consume: %v\n%s", err, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("consume: output missing %q; got: %s", want, out)
	}
	t.Logf("kafka produce/consume roundtrip ok")
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
