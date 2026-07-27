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

// Package mosquitto is a gVisor compatibility test for the Eclipse Mosquitto
// MQTT broker.
//
// The Mosquitto version under test is pinned in
// images/compatibility/mosquitto/mosquitto/Dockerfile.
package mosquitto

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
	mosquittoImage = "compatibility/mosquitto/mosquitto"

	topic = "gv/test"
	want  = "gvisor-msg"

	readyTimeout = 1 * time.Minute
	pollInterval = 2 * time.Second
)

const mosquittoConfig = `listener 1883 0.0.0.0
allow_anonymous true
`

func TestMosquitto(t *testing.T) {
	ctx := context.Background()

	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	opts := dockerutil.RunOpts{Image: mosquittoImage}
	c.CopyFiles(&opts, "/mosquitto/config", compatibility.WriteConfigFile(t, "mosquitto.conf", mosquittoConfig))
	if err := c.Spawn(ctx, opts); err != nil {
		t.Fatalf("failed to start mosquitto: %v", err)
	}

	// Wait for the broker to accept a publish.
	compatibility.Poll(ctx, t, "mosquitto to accept connections", readyTimeout, pollInterval, func() error {
		if out, err := c.Exec(ctx, dockerutil.ExecOpts{}, "mosquitto_pub", "-t", "gv/ready", "-m", "ping"); err != nil {
			return fmt.Errorf("mosquitto_pub: %v (%s)", err, out)
		}
		return nil
	})

	// Publish a retained message.
	if out, err := c.Exec(ctx, dockerutil.ExecOpts{}, "mosquitto_pub", "-t", topic, "-m", want, "-r"); err != nil {
		t.Fatalf("publish: %v\n%s", err, out)
	}

	// Subscribe and read the retained message back (exit after one message).
	out, err := c.Exec(ctx, dockerutil.ExecOpts{}, "mosquitto_sub", "-t", topic, "-C", "1", "-W", "10")
	if err != nil {
		t.Fatalf("subscribe: %v\n%s", err, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("subscribe: output missing %q; got: %q", want, strings.TrimSpace(out))
	}
	t.Logf("mosquitto publish/subscribe roundtrip ok")
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
