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

// Package redis is a gVisor compatibility test for Redis.
//
// The Redis version under test is pinned in
// images/compatibility/redis/redis/Dockerfile.
package redis

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
	redisImage = "compatibility/redis/redis"

	key  = "gv-key"
	want = "gvisor-value"

	readyTimeout = 2 * time.Minute
	pollInterval = 2 * time.Second
)

func TestRedis(t *testing.T) {
	ctx := context.Background()

	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	if err := c.Spawn(ctx, dockerutil.RunOpts{Image: redisImage}); err != nil {
		t.Fatalf("failed to start redis: %v", err)
	}

	cli := func(args ...string) (string, error) {
		return c.Exec(ctx, dockerutil.ExecOpts{}, append([]string{"redis-cli"}, args...)...)
	}

	// Wait for the server to respond to PING.
	compatibility.Poll(ctx, t, "redis to respond to PING", readyTimeout, pollInterval, func() error {
		out, err := cli("ping")
		if err != nil {
			return err
		}
		if !strings.Contains(out, "PONG") {
			return fmt.Errorf("PING returned %q", strings.TrimSpace(out))
		}
		return nil
	})

	// SET then GET the key back.
	if out, err := cli("set", key, want); err != nil {
		t.Fatalf("SET failed: %v\n%s", err, out)
	}
	out, err := cli("get", key)
	if err != nil {
		t.Fatalf("GET failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("GET %s: got %q, want to contain %q", key, strings.TrimSpace(out), want)
	}
	t.Logf("redis roundtrip ok")
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
