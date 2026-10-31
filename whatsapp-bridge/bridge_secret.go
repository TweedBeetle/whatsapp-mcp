package main

// Shared secret on POST /api/send (prompt-injection batch 2, part P3c; security-lead 7f01ceeb, 2026-10-22).
//
// Any local process can POST /api/send on a loopback port and send as the line. The fix is a shared
// secret: wa.py reads ~/.config/whatsapp-bridge/api-secret and sends it as the X-WA-Bridge-Secret header;
// the bridge compares it with the same file (read per request, so rotating it needs no restart).
//
// REPORT-ONLY: a request with no header, a wrong header, or no secret configured is logged (stdout and
// ~/.claude/state/injection-b2/wa-bridge-secret.jsonl: time, line, status, remote address, user agent,
// client hint; never the message) and STILL SERVED. WA_BRIDGE_SECRET_ENFORCE=1 in the bridge's
// environment makes it refuse with 403 instead; only security-lead sets that, after the replay.
// WA_BRIDGE_SECRET_DISABLE=1 skips the check (logged once per process as KILL-SWITCH-ACTIVE).
// The file is identical in both bridges.
//
// Fail closed under enforce (security-lead, 2026-10-31, prose-lint send-timing reverify-3 L4): the secret is the
// browser-CSRF defence (neither bridge answers CORS and no handler checked Content-Type, so any page open in Chrome
// could POST a text/plain body holding JSON to /api/send with no preflight). Under WA_BRIDGE_SECRET_ENFORCE=1:
// (a) a secret file that is missing, empty or unreadable refuses every guarded request (`no-secret-configured
// refused`), where it used to serve everything; (b) a panic in this check refuses (report-only still allows);
// (c) a POST whose Content-Type is not application/json is refused (`not-json`), which forces a browser preflight.
// WA_BRIDGE_SECRET_DISABLE stays the one logged allow path.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var bridgeSecretKillOnce sync.Once

func bridgeSecretStateDir() string {
	if d := os.Getenv("INJECTION_B2_STATE_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "state", "injection-b2")
}

func bridgeSecretAppend(name string, row map[string]interface{}) {
	defer func() { recover() }()
	dir := bridgeSecretStateDir()
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	b, err := json.Marshal(row)
	if err != nil {
		return
	}
	f.Write(append(b, '\n'))
}

// bridgeSecretJSON reports whether a request declares a JSON body (application/json, any parameters).
func bridgeSecretJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// bridgeSecretAllow reports whether the request may be served. It returns false only under
// WA_BRIDGE_SECRET_ENFORCE=1: no usable secret configured, a missing or wrong header, a POST that is not JSON,
// or a failure of this check itself.
func bridgeSecretAllow(r *http.Request, line string) (allow bool) {
	enforceEnv := os.Getenv("WA_BRIDGE_SECRET_ENFORCE") == "1"
	allow = true
	defer func() {
		if recover() != nil {
			allow = !enforceEnv
		}
	}()
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if os.Getenv("WA_BRIDGE_SECRET_DISABLE") != "" {
		bridgeSecretKillOnce.Do(func() {
			bridgeSecretAppend("kill-switch.jsonl", map[string]interface{}{
				"ts": now, "check": "kill-switch", "event": "KILL-SWITCH-ACTIVE", "hook": "wa-bridge-" + line,
				"session_id": fmt.Sprintf("bridge:%s:pid%d", line, os.Getpid()), "cwd": "",
				"variable": "WA_BRIDGE_SECRET_DISABLE", "source": "process-env (LaunchAgent)", "kind": "kill-switch"})
		})
		return true
	}
	path := os.Getenv("WA_BRIDGE_SECRET_FILE")
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".config", "whatsapp-bridge", "api-secret")
	}
	want := ""
	if b, err := os.ReadFile(path); err == nil {
		want = strings.TrimSpace(string(b))
	}
	got := strings.TrimSpace(r.Header.Get("X-WA-Bridge-Secret"))
	status := "ok"
	switch {
	case want == "":
		status = "no-secret-configured"
	case got == "":
		status = "missing-header"
	case subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1:
		status = "bad-header"
	case r.Method == http.MethodPost && !bridgeSecretJSON(r):
		status = "not-json"
	}
	if status == "ok" {
		return true
	}
	enforce := enforceEnv
	verdict := "would-refuse"
	if enforce {
		verdict = "refused"
	}
	fmt.Printf("[injection-b2 wa-bridge-secret] %s %s %s on the %s line: %s (remote %s, agent %q); %s\n",
		verdict, r.Method, r.URL.Path, line, status, r.RemoteAddr, r.UserAgent(),
		map[bool]string{true: "REFUSED", false: "served (report-only)"}[enforce])
	bridgeSecretAppend("wa-bridge-secret.jsonl", map[string]interface{}{
		"ts": now, "check": "wa-bridge-secret", "channel": "whatsapp-bridge", "line": line,
		"tool": r.Method + " " + r.URL.Path, "rule": status, "verdict": verdict, "enforce": enforce,
		"remote": r.RemoteAddr, "user_agent": r.UserAgent(), "client": r.Header.Get("X-WA-Client"),
	})
	return !enforce
}
