package main

// The shared secret on every state-changing request to the PERSONAL bridge (prose-lint send-timing second
// re-verification R6, 2026-10-29). bridge_secret.go checks POST /api/send inside its handler; the revoke and group
// endpoints added later (/api/revoke deletes a message for everyone, /api/group/* create groups and communities and
// change their description and photo) took no secret, so any local process could change what other people see on
// Christo's personal line. This wraps the whole mux instead of each handler, so an endpoint added later is covered
// too: every request that is not GET, HEAD or OPTIONS goes through bridgeSecretAllow, except /api/send, which
// already checks in its handler (checking twice would log twice). Same report-only and enforce switches.

import "net/http"

func bridgeSecretGuard(next http.Handler, line string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.URL.Path != "/api/send" && !bridgeSecretAllow(r, line) {
				http.Error(w, "Forbidden: missing or wrong X-WA-Bridge-Secret", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
