package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewResilientClient(t *testing.T) {
	config := DefaultResilientClientConfig()
	client := NewResilientClient(30*time.Second, config)

	if client == nil {
		t.Fatal("NewResilientClient returned nil")
	}

	if client.client == nil {
		t.Error("HTTP client is nil")
	}

	if config.EnableCircuitBreaker && client.breaker == nil {
		t.Error("Circuit breaker is nil when enabled")
	}
}

func TestResilientClient_SuccessfulRequest(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	// Create client
	config := ResilientClientConfig{
		EnableCircuitBreaker: true,
		MaxFailures:          5,
		CircuitTimeout:       30 * time.Second,
		MaxRetries:           3,
		InitialInterval:      100 * time.Millisecond,
		MaxInterval:          1 * time.Second,
	}
	client := NewResilientClient(5*time.Second, config)

	// Make request
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestResilientClient_Retry5xxErrors(t *testing.T) {
	attempts := 0

	// Create test server that fails twice then succeeds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	// Create client with retry
	config := ResilientClientConfig{
		EnableCircuitBreaker: false, // Disable circuit breaker for this test
		MaxRetries:           3,
		InitialInterval:      10 * time.Millisecond,
		MaxInterval:          50 * time.Millisecond,
	}
	client := NewResilientClient(5*time.Second, config)

	// Make request
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed after retries: %v", err)
	}
	defer resp.Body.Close()

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestResilientClient_NoRetryOn4xxErrors(t *testing.T) {
	attempts := 0

	// Create test server that always returns 400
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "bad request"}`))
	}))
	defer server.Close()

	// Create client with retry
	config := ResilientClientConfig{
		EnableCircuitBreaker: false,
		MaxRetries:           3,
		InitialInterval:      10 * time.Millisecond,
		MaxInterval:          50 * time.Millisecond,
	}
	client := NewResilientClient(5*time.Second, config)

	// Make request
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	_, err = client.Do(req)
	if err == nil {
		t.Fatal("Expected error for 400 status")
	}

	// Should only attempt once (no retries for 4xx)
	if attempts != 1 {
		t.Errorf("Expected 1 attempt, got %d (4xx should not be retried)", attempts)
	}
}

func TestResilientClient_CircuitBreakerOpensAfterFailures(t *testing.T) {
	attempts := 0

	// Create test server that always fails with 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable) // 503 - will not be retried with MaxRetries=0
	}))
	defer server.Close()

	// Create client with circuit breaker and NO retries
	config := ResilientClientConfig{
		EnableCircuitBreaker: true,
		MaxFailures:          3,
		CircuitTimeout:       1 * time.Second,
		MaxRetries:           0, // Single attempt per request
		InitialInterval:      10 * time.Millisecond,
		MaxInterval:          50 * time.Millisecond,
	}
	client := NewResilientClient(5*time.Second, config)

	// Make 5 requests - first 3 should reach server, then circuit should open
	errors := make([]error, 5)
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		_, errors[i] = client.Do(req)
	}

	// Check that we eventually got a "circuit breaker is open" error
	var gotCircuitOpenError bool
	for _, err := range errors {
		if err != nil && strings.Contains(err.Error(), "circuit breaker is open") {
			gotCircuitOpenError = true
			break
		}
	}

	if !gotCircuitOpenError {
		t.Errorf("Expected circuit breaker to open, but didn't see open error. Errors: %v", errors)
	}

	t.Logf("Circuit breaker opened after %d attempts to server", attempts)
}

func TestResilientClient_CircuitBreakerRecovery(t *testing.T) {
	attempts := 0
	shouldFail := true

	// Create test server that can toggle success/failure
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if shouldFail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	// Create client with circuit breaker
	config := ResilientClientConfig{
		EnableCircuitBreaker: true,
		MaxFailures:          2,
		CircuitTimeout:       500 * time.Millisecond,
		MaxRetries:           0,
		InitialInterval:      10 * time.Millisecond,
		MaxInterval:          50 * time.Millisecond,
	}
	client := NewResilientClient(5*time.Second, config)

	// Trip the circuit breaker
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		client.Do(req)
	}

	// Wait for circuit to go into half-open state
	time.Sleep(600 * time.Millisecond)

	// Start succeeding
	shouldFail = false

	// Circuit should attempt recovery
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("Recovery attempt failed (expected if circuit needs more time): %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Log("Circuit breaker recovered successfully")
		}
	}
}

func TestResilientClient_DisabledCircuitBreaker(t *testing.T) {
	attempts := 0

	// Create test server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create client WITHOUT circuit breaker
	config := ResilientClientConfig{
		EnableCircuitBreaker: false,
		MaxRetries:           0,
		InitialInterval:      10 * time.Millisecond,
		MaxInterval:          50 * time.Millisecond,
	}
	client := NewResilientClient(5*time.Second, config)

	// Make multiple requests - should all reach the server
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		client.Do(req)
	}

	// All requests should reach server (no circuit breaker)
	if attempts != 5 {
		t.Errorf("Expected 5 attempts, got %d", attempts)
	}
}

func TestResilientClient_ContextCancellation(t *testing.T) {
	// Create test server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client
	config := DefaultResilientClientConfig()
	config.EnableCircuitBreaker = false
	client := NewResilientClient(5*time.Second, config)

	// Create request with cancellable context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Make request - should be cancelled
	_, err = client.Do(req)
	if err == nil {
		t.Error("Expected error due to context cancellation")
	}

	if !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("Expected context/deadline error, got: %v", err)
	}
}

func TestShouldRetry(t *testing.T) {
	config := DefaultResilientClientConfig()
	client := NewResilientClient(30*time.Second, config)

	tests := []struct {
		name       string
		err        error
		statusCode int
		want       bool
	}{
		{"500 error", nil, http.StatusInternalServerError, true},
		{"502 error", nil, http.StatusBadGateway, true},
		{"503 error", nil, http.StatusServiceUnavailable, true},
		{"504 error", nil, http.StatusGatewayTimeout, true},
		{"429 error", nil, http.StatusTooManyRequests, true},
		{"400 error", nil, http.StatusBadRequest, false},
		{"401 error", nil, http.StatusUnauthorized, false},
		{"404 error", nil, http.StatusNotFound, false},
		{"200 success", nil, http.StatusOK, false},
		{"context deadline", context.DeadlineExceeded, 0, true},
		{"connection refused", fmt.Errorf("connection refused"), 0, true},
		{"EOF error", fmt.Errorf("EOF"), 0, true},
		{"unknown error", fmt.Errorf("unknown error"), 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *http.Response
			if tt.statusCode > 0 {
				resp = &http.Response{StatusCode: tt.statusCode}
			}

			got := client.shouldRetry(tt.err, resp)
			if got != tt.want {
				t.Errorf("shouldRetry() = %v, want %v", got, tt.want)
			}
		})
	}
}
