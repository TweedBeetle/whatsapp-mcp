package main

// Tests for bridge_secret_post.go: the guard around a stand-in mux with the bridge's routes, a fixture secret and
// a scratch ledger. No handler here touches WhatsApp. Run: go test -run BridgeSecretGuard .

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func guardServer(t *testing.T, enforce string) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	secret := filepath.Join(dir, "api-secret")
	if err := os.WriteFile(secret, []byte("fixture-secret-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WA_BRIDGE_SECRET_FILE", secret)
	t.Setenv("INJECTION_B2_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("WA_BRIDGE_SECRET_ENFORCE", enforce)
	t.Setenv("WA_BRIDGE_SECRET_DISABLE", "")
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	for _, p := range []string{"/api/send", "/api/revoke", "/api/download", "/api/whoami", "/api/group/create",
		"/api/group/create_community", "/api/group/invite", "/api/group/describe", "/api/group/photo",
		"/api/group/info", "/api/not-yet-written"} {
		mux.HandleFunc(p, ok)
	}
	srv := httptest.NewServer(bridgeSecretGuard(mux, "test"))
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, method, url, secret string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-WA-Bridge-Secret", secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestBridgeSecretGuardRefusesEveryPostWithoutTheSecret(t *testing.T) {
	srv := guardServer(t, "1")
	for _, p := range []string{"/api/revoke", "/api/download", "/api/group/create", "/api/group/create_community",
		"/api/group/invite", "/api/group/describe", "/api/group/photo", "/api/not-yet-written"} {
		if got := call(t, http.MethodPost, srv.URL+p, ""); got != http.StatusForbidden {
			t.Errorf("POST %s with no secret: %d, want 403", p, got)
		}
		if got := call(t, http.MethodPost, srv.URL+p, "wrong"); got != http.StatusForbidden {
			t.Errorf("POST %s with a wrong secret: %d, want 403", p, got)
		}
		if got := call(t, http.MethodPost, srv.URL+p, "fixture-secret-123"); got != http.StatusOK {
			t.Errorf("POST %s with the secret: %d, want 200", p, got)
		}
	}
	if got := call(t, http.MethodDelete, srv.URL+"/api/revoke", ""); got != http.StatusForbidden {
		t.Errorf("DELETE with no secret: %d, want 403", got)
	}
}

func TestBridgeSecretGuardLeavesReadsAndSendAlone(t *testing.T) {
	srv := guardServer(t, "1")
	for _, p := range []string{"/api/whoami", "/api/group/info"} {
		if got := call(t, http.MethodGet, srv.URL+p, ""); got != http.StatusOK {
			t.Errorf("GET %s: %d, want 200", p, got)
		}
	}
	// /api/send checks the secret in its own handler (bridge_secret.go); the guard does not check it twice.
	if got := call(t, http.MethodPost, srv.URL+"/api/send", ""); got != http.StatusOK {
		t.Errorf("POST /api/send reached its handler: %d, want 200 from the stand-in", got)
	}
}

func TestBridgeSecretGuardReportOnlyServes(t *testing.T) {
	srv := guardServer(t, "")
	if got := call(t, http.MethodPost, srv.URL+"/api/revoke", ""); got != http.StatusOK {
		t.Errorf("report-only POST /api/revoke: %d, want 200", got)
	}
}
