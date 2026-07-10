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

// Package postgresql is a gVisor compatibility test for PostgreSQL.
//
// The PostgreSQL version under test is pinned in
// images/compatibility/postgresql/postgresql/Dockerfile.
package postgresql

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
	pgImage = "compatibility/postgresql/postgresql"

	dbName     = "gvisor"
	dbUser     = "gvisor"
	dbPassword = "gvisorpass"

	want = "gvisor-row"

	readyTimeout = 2 * time.Minute
	pollInterval = 2 * time.Second
)

func TestPostgreSQL(t *testing.T) {
	ctx := context.Background()

	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	if err := c.Spawn(ctx, dockerutil.RunOpts{
		Image: pgImage,
		Env: []string{
			"POSTGRES_DB=" + dbName,
			"POSTGRES_USER=" + dbUser,
			"POSTGRES_PASSWORD=" + dbPassword,
		},
	}); err != nil {
		t.Fatalf("failed to start postgres: %v", err)
	}

	// Wait until Postgres accepts connections over TCP.
	compatibility.Poll(ctx, t, "postgres to accept connections", readyTimeout, pollInterval, func() error {
		if out, err := c.Exec(ctx, dockerutil.ExecOpts{}, "pg_isready", "-h", "127.0.0.1", "-U", dbUser, "-d", dbName); err != nil {
			return fmt.Errorf("pg_isready: %v (%s)", err, out)
		}
		return nil
	})

	// Write a row and read it back via psql (local socket auth is "trust").
	out, err := c.Exec(ctx, dockerutil.ExecOpts{}, "psql", "-U", dbUser, "-d", dbName, "-tAc",
		"CREATE TABLE gv (id int PRIMARY KEY, v text); "+
			"INSERT INTO gv VALUES (1, '"+want+"'); "+
			"SELECT v FROM gv WHERE id = 1;")
	if err != nil {
		t.Fatalf("psql roundtrip failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("psql roundtrip: output missing %q; got: %s", want, out)
	}
	t.Logf("postgres roundtrip ok: %s", strings.TrimSpace(out))
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
