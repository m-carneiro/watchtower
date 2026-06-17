package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateWebhook(t *testing.T) {
	const secret = "super-secret-token"

	tests := []struct {
		name       string
		configured string // value for SENTINELONE_WEBHOOK_SECRET
		authHeader string
		want       bool
	}{
		{"fail closed when secret unset", "", "Bearer " + secret, false},
		{"valid credentials", secret, "Bearer " + secret, true},
		{"wrong token", secret, "Bearer nope", false},
		{"missing bearer prefix", secret, secret, false},
		{"empty header", secret, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SENTINELONE_WEBHOOK_SECRET", tc.configured)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/sentinelone", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()

			if got := authenticateWebhook(rec, req); got != tc.want {
				t.Fatalf("authenticateWebhook() = %v, want %v", got, tc.want)
			}
			if !tc.want && rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}
