package main

// Tests for bridge_secret.go: a real HTTP server on a scratch loopback port wrapping bridgeSecretAllow
// the way /api/send does, with a fixture secret file and a scratch ledger dir. Nothing reaches WhatsApp.
// Run: go test -run BridgeSecret .

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bridgeSecretServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	secret := filepath.Join(dir, "api-secret")
	if err := os.WriteFile(secret, []byte("fixture-secret-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WA_BRIDGE_SECRET_FILE", secret)
	t.Setenv("INJECTION_B2_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("WA_BRIDGE_SECRET_ENFORCE", "")
	t.Setenv("WA_BRIDGE_SECRET_DISABLE", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bridgeSecretAllow(r, "test") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, filepath.Join(dir, "state")
}

func post(t *testing.T, url, secret string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/api/send", strings.NewReader(`{"recipient":"x","message":"y"}`))
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

func ledgerRules(t *testing.T, state string) []string {
	f, err := os.Open(filepath.Join(state, "wa-bridge-secret.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var row map[string]interface{}
		if json.Unmarshal(sc.Bytes(), &row) == nil {
			if strings.Contains(sc.Text(), "\"message\"") {
				t.Fatalf("ledger row carries a message field: %s", sc.Text())
			}
			out = append(out, row["rule"].(string)+"/"+row["verdict"].(string))
		}
	}
	return out
}

func TestBridgeSecretReportOnly(t *testing.T) {
	srv, state := bridgeSecretServer(t)
	if c := post(t, srv.URL, "fixture-secret-123"); c != 200 {
		t.Fatalf("right secret: %d", c)
	}
	if c := post(t, srv.URL, ""); c != 200 {
		t.Fatalf("missing header must still be served in report-only: %d", c)
	}
	if c := post(t, srv.URL, "wrong"); c != 200 {
		t.Fatalf("wrong header must still be served in report-only: %d", c)
	}
	got := strings.Join(ledgerRules(t, state), ",")
	if got != "missing-header/would-refuse,bad-header/would-refuse" {
		t.Fatalf("ledger: %q", got)
	}
}

func TestBridgeSecretEnforce(t *testing.T) {
	srv, state := bridgeSecretServer(t)
	t.Setenv("WA_BRIDGE_SECRET_ENFORCE", "1")
	if c := post(t, srv.URL, ""); c != 403 {
		t.Fatalf("enforce, missing header: %d", c)
	}
	if c := post(t, srv.URL, "fixture-secret-123"); c != 200 {
		t.Fatalf("enforce, right secret: %d", c)
	}
	if got := strings.Join(ledgerRules(t, state), ","); got != "missing-header/refused" {
		t.Fatalf("ledger: %q", got)
	}
}

func TestBridgeSecretNoSecretConfiguredNeverRefuses(t *testing.T) {
	srv, state := bridgeSecretServer(t)
	t.Setenv("WA_BRIDGE_SECRET_FILE", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("WA_BRIDGE_SECRET_ENFORCE", "1")
	if c := post(t, srv.URL, ""); c != 200 {
		t.Fatalf("no secret configured must serve even under enforce: %d", c)
	}
	if got := strings.Join(ledgerRules(t, state), ","); got != "no-secret-configured/would-refuse" {
		t.Fatalf("ledger: %q", got)
	}
}

func TestBridgeSecretKillSwitchLogged(t *testing.T) {
	srv, state := bridgeSecretServer(t)
	t.Setenv("WA_BRIDGE_SECRET_DISABLE", "1")
	t.Setenv("WA_BRIDGE_SECRET_ENFORCE", "1")
	if c := post(t, srv.URL, ""); c != 200 {
		t.Fatalf("disabled: %d", c)
	}
	b, _ := os.ReadFile(filepath.Join(state, "kill-switch.jsonl"))
	if !strings.Contains(string(b), "WA_BRIDGE_SECRET_DISABLE") {
		t.Fatalf("kill switch not logged: %q", b)
	}
}
