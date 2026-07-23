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

// Package rabbitmq is a gVisor compatibility test for RabbitMQ.
//
// The RabbitMQ version under test is pinned in
// images/compatibility/rabbitmq/rabbitmq/Dockerfile.
package rabbitmq

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/compatibility"
)

const (
	rabbitmqImage = "compatibility/rabbitmq/rabbitmq"

	user     = "gvisor"
	password = "gvisorpass"
	mgmtPort = 15672

	queue = "gv"
	want  = "gvisor-msg"

	readyTimeout = 3 * time.Minute
	pollInterval = 3 * time.Second
)

func TestRabbitMQ(t *testing.T) {
	ctx := context.Background()

	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	if err := c.Spawn(ctx, dockerutil.RunOpts{
		Image: rabbitmqImage,
		Env: []string{
			"RABBITMQ_DEFAULT_USER=" + user,
			"RABBITMQ_DEFAULT_PASS=" + password,
		},
	}); err != nil {
		t.Fatalf("failed to start rabbitmq: %v", err)
	}

	ip, err := c.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("failed to find rabbitmq IP: %v", err)
	}
	base := fmt.Sprintf("http://%s:%d", ip.String(), mgmtPort)

	// Wait for the management API to be up.
	compatibility.Poll(ctx, t, "rabbitmq management API to be ready", readyTimeout, pollInterval, func() error {
		status, _, err := compatibility.Request{URL: base + "/api/overview", Username: user, Password: password}.Do()
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("GET /api/overview: status %d", status)
		}
		return nil
	})

	// Declare a durable queue on the default vhost ("/" urlencoded).
	defaultVHost := "%2f"
	compatibility.Request{
		Method:      http.MethodPut,
		URL:         base + "/api/queues/" + defaultVHost + "/" + queue,
		ContentType: "application/json",
		Username:    user,
		Password:    password,
		Body:        `{"durable":true}`,
	}.DoOrFatal(t, http.StatusCreated)

	// Publish a message through the default exchange, routed by queue name.
	published := compatibility.Request{
		Method:      http.MethodPost,
		URL:         base + "/api/exchanges/" + defaultVHost + "/amq.default/publish",
		ContentType: "application/json",
		Username:    user,
		Password:    password,
		Body: fmt.Sprintf(`{"properties":{},"routing_key":%q,"payload":%q,"payload_encoding":"string"}`,
			queue, want),
	}.DoOrFatal(t, http.StatusOK)
	if !strings.Contains(published, `"routed":true`) {
		t.Fatalf("publish: message not routed; body: %s", published)
	}

	// Read it back.
	got := compatibility.Request{
		Method:      http.MethodPost,
		URL:         base + "/api/queues/" + defaultVHost + "/" + queue + "/get",
		ContentType: "application/json",
		Username:    user,
		Password:    password,
		Body:        `{"count":1,"ackmode":"ack_requeue_false","encoding":"auto"}`,
	}.DoOrFatal(t, http.StatusOK)
	if !strings.Contains(got, want) {
		t.Fatalf("get: expected payload %q; body: %s", want, got)
	}
	t.Logf("rabbitmq publish/get roundtrip ok")
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
