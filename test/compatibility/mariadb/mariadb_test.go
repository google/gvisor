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

// Package mariadb is a gVisor compatibility test for MariaDB.
//
// The MariaDB version under test is pinned in
// images/compatibility/mariadb/mariadb/Dockerfile.
package mariadb

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
	mariadbImage = "compatibility/mariadb/mariadb"

	dbName         = "gvisor"
	dbUser         = "gvisor"
	dbPassword     = "gvisorpass"
	dbRootPassword = "rootpass"

	want = "gvisor-row"

	readyTimeout = 3 * time.Minute
	pollInterval = 2 * time.Second
)

func TestMariaDB(t *testing.T) {
	ctx := context.Background()

	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	if err := c.Spawn(ctx, dockerutil.RunOpts{
		Image: mariadbImage,
		Env: []string{
			"MARIADB_ROOT_PASSWORD=" + dbRootPassword,
			"MARIADB_DATABASE=" + dbName,
			"MARIADB_USER=" + dbUser,
			"MARIADB_PASSWORD=" + dbPassword,
		},
	}); err != nil {
		t.Fatalf("failed to start mariadb: %v", err)
	}

	// Wait for MariaDB to be ready.
	query := func(sql string) (string, error) {
		return c.Exec(ctx, dockerutil.ExecOpts{},
			"mariadb", "-u"+dbUser, "-p"+dbPassword, dbName, "-e", sql)
	}
	compatibility.Poll(ctx, t, "mariadb to accept queries", readyTimeout, pollInterval, func() error {
		if out, err := query("SELECT 1"); err != nil {
			return fmt.Errorf("mariadb query: %v (%s)", err, out)
		}
		return nil
	})

	// Write a row and read it back.
	out, err := query("CREATE TABLE gv (id int PRIMARY KEY, v varchar(32)); " +
		"INSERT INTO gv VALUES (1, '" + want + "'); " +
		"SELECT v FROM gv WHERE id = 1;")
	if err != nil {
		t.Fatalf("mariadb roundtrip failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("mariadb roundtrip: output missing %q; got: %s", want, out)
	}
	t.Logf("mariadb roundtrip ok")
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
