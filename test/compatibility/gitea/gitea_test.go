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

// Package gitea is a gVisor compatibility test for Gitea backed by PostgreSQL.
//
// The Gitea version under test is specified in images/compatibility/gitea/Dockerfile.
package gitea

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
	giteaImage    = "compatibility/gitea/gitea"
	postgresImage = "compatibility/gitea/postgres"

	dbName     = "gitea"
	dbUser     = "gitea"
	dbPassword = "giteapass"

	adminUser     = "gvisoradmin"
	adminPassword = "gvisor-Test-1234"
	adminEmail    = "admin@example.com"

	giteaPort = 3000

	readyTimeout = 3 * time.Minute
	pollInterval = 2 * time.Second
)

func TestGitea(t *testing.T) {
	ctx := context.Background()

	// PostgreSQL backend.
	db := dockerutil.MakeContainer(ctx, t)
	defer db.CleanUp(ctx)
	if err := db.Spawn(ctx, dockerutil.RunOpts{
		Image: postgresImage,
		Env: []string{
			"POSTGRES_DB=" + dbName,
			"POSTGRES_USER=" + dbUser,
			"POSTGRES_PASSWORD=" + dbPassword,
		},
	}); err != nil {
		t.Fatalf("failed to start postgres: %v", err)
	}

	// Wait until Postgres accepts connections before starting Gitea.
	compatibility.Poll(ctx, t, "postgres to accept connections", readyTimeout, pollInterval, func() error {
		out, err := db.Exec(ctx, dockerutil.ExecOpts{}, "pg_isready", "-U", dbUser, "-d", dbName)
		if err != nil {
			return fmt.Errorf("pg_isready: %v (%s)", err, out)
		}
		return nil
	})

	// Gitea app container.
	gitea := dockerutil.MakeContainer(ctx, t)
	defer gitea.CleanUp(ctx)
	if err := gitea.Spawn(ctx, dockerutil.RunOpts{
		Image: giteaImage,
		Links: []string{db.MakeLink("db")},
		Env: []string{
			"GITEA__database__DB_TYPE=postgres",
			"GITEA__database__HOST=db:5432",
			"GITEA__database__NAME=" + dbName,
			"GITEA__database__USER=" + dbUser,
			"GITEA__database__PASSWD=" + dbPassword,
			// Skip the interactive web install wizard; configure via env instead.
			"GITEA__security__INSTALL_LOCK=true",
		},
	}); err != nil {
		t.Fatalf("failed to start gitea: %v", err)
	}

	ip, err := gitea.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("failed to find gitea IP: %v", err)
	}
	base := fmt.Sprintf("http://%s:%d", ip.String(), giteaPort)

	// Wait for Gitea's API to be ready.
	compatibility.Poll(ctx, t, "gitea API to be ready", readyTimeout, pollInterval, func() error {
		status, _, err := compatibility.Get(base + "/api/v1/version")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("GET /api/v1/version: status %d", status)
		}
		return nil
	})

	// Log the running version.
	if _, body, err := compatibility.Get(base + "/api/v1/version"); err == nil {
		t.Logf("gitea version: %s", strings.TrimSpace(body))
	}

	// Create an admin user via the Gitea CLI.
	if out, err := gitea.Exec(ctx, dockerutil.ExecOpts{User: "git"},
		"gitea", "admin", "user", "create",
		"--admin",
		"--username", adminUser,
		"--password", adminPassword,
		"--email", adminEmail,
		"--must-change-password=false",
	); err != nil {
		t.Fatalf("failed to create admin user: %v\n%s", err, out)
	}

	// Create a repository via the API.
	compatibility.Request{
		Method:      http.MethodPost,
		URL:         base + "/api/v1/user/repos",
		ContentType: "application/json",
		Body:        `{"name":"gvisor-test","auto_init":true}`,
		Username:    adminUser,
		Password:    adminPassword,
	}.DoOrFatal(t, http.StatusCreated)

	// Read the repository back via the API.
	status, repoBody, err := compatibility.Get(base + "/api/v1/repos/" + adminUser + "/gvisor-test")
	if err != nil {
		t.Fatalf("read-back request failed: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("read repo back: got status %d, want %d; body: %s", status, http.StatusOK, repoBody)
	}
	want := `"name":"gvisor-test"`
	if !strings.Contains(repoBody, want) {
		t.Fatalf("read repo back: body missing %q; got: %s", want, repoBody)
	}
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
