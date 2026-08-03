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

// Package keycloak is a gVisor compatibility test for Keycloak.
//
// The Keycloak version under test is pinned in
// images/compatibility/keycloak/keycloak/Dockerfile.
package keycloak

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/compatibility"
)

const (
	keycloakImage = "compatibility/keycloak/keycloak"
	keycloakPort  = 8080

	adminUser     = "admin"
	adminPassword = "admin-gvtest-1234"

	realm    = "gvtest"
	appUser  = "alice"
	appPass  = "alicepw"
	appCl    = "gvapp"
	adminCli = "admin-cli"

	readyTimeout = 4 * time.Minute
	pollInterval = 3 * time.Second
)

func TestKeycloak(t *testing.T) {
	ctx := context.Background()

	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	if err := c.Spawn(ctx, dockerutil.RunOpts{
		Image: keycloakImage,
		Env: []string{
			"KC_BOOTSTRAP_ADMIN_USERNAME=" + adminUser,
			"KC_BOOTSTRAP_ADMIN_PASSWORD=" + adminPassword,
			"KC_HEALTH_ENABLED=true",
		},
	}, "start-dev"); err != nil {
		t.Fatalf("failed to start keycloak: %v", err)
	}

	ip, err := c.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("failed to find keycloak IP: %v", err)
	}
	base := fmt.Sprintf("http://%s:%d", ip.String(), keycloakPort)

	// Wait for the master realm to be served.
	compatibility.Poll(ctx, t, "keycloak master realm to be ready", readyTimeout, pollInterval, func() error {
		status, _, err := compatibility.Get(base + "/realms/master")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("GET /realms/master: status %d", status)
		}
		return nil
	})

	// Authenticate as the bootstrap admin.
	adminToken := token(t, base, "master", adminCli, adminUser, adminPassword)

	bearer := map[string]string{"Authorization": "Bearer " + adminToken}
	adminJSON := func(method, path, body string, want int) {
		compatibility.Request{
			Method: method, URL: base + path, ContentType: "application/json",
			Headers: bearer, Body: body,
		}.DoOrFatal(t, want)
	}

	// Create a realm, a user (with a password), and a public direct-grant client.
	adminJSON(http.MethodPost, "/admin/realms",
		fmt.Sprintf(`{"realm":%q,"enabled":true}`, realm), http.StatusCreated)
	// A complete profile (name/email) and no required actions are needed, else
	// Keycloak's "Verify Profile" action blocks the direct-grant login below.
	adminJSON(http.MethodPost, "/admin/realms/"+realm+"/users",
		fmt.Sprintf(`{"username":%q,"enabled":true,"emailVerified":true,"firstName":"Alice","lastName":"Test",`+
			`"email":"alice@example.com","requiredActions":[],`+
			`"credentials":[{"type":"password","value":%q,"temporary":false}]}`, appUser, appPass),
		http.StatusCreated)
	adminJSON(http.MethodPost, "/admin/realms/"+realm+"/clients",
		fmt.Sprintf(`{"clientId":%q,"publicClient":true,"directAccessGrantsEnabled":true,"enabled":true}`, appCl),
		http.StatusCreated)

	// Verify the realm exists.
	adminJSON(http.MethodGet, "/admin/realms/"+realm, "", http.StatusOK)

	// Mint a token for the new user in the new realm: exercises JWT signing and a
	// DB-backed user credential.
	if userToken := token(t, base, realm, appCl, appUser, appPass); userToken == "" {
		t.Fatalf("minted user token is empty")
	}
	t.Logf("keycloak: created realm/user/client and minted a user token")
}

// token performs an OpenID Connect password grant and returns the access token.
func token(t *testing.T, base, realm, clientID, username, password string) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
	}
	body := compatibility.Request{
		Method:      http.MethodPost,
		URL:         base + "/realms/" + realm + "/protocol/openid-connect/token",
		ContentType: "application/x-www-form-urlencoded",
		Body:        form.Encode(),
	}.DoOrFatal(t, http.StatusOK)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token (%s/%s): no access_token (%v); body: %s", realm, clientID, err, body)
	}
	return tok.AccessToken
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
