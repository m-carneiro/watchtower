package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildPrompt(t *testing.T) {
	triager := &LLMTriager{}

	threat := ThreatContext{
		AlertID:        "TEST-001",
		ThreatName:     "Suspicious Activity",
		Classification: "Malware",
		Endpoint:       "DESKTOP-01",
		OSType:         "windows",
		IOCs: []IOCContext{
			{
				Type:        "IPV4",
				Value:       "192.0.2.1",
				InDatabase:  true,
				Sources:     []string{"alienvault-otx", "urlhaus"},
				ThreatTypes: []string{"c2_server"},
				Tags:        []string{"malware", "c2"},
				FirstSeen:   time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	prompt := triager.buildPrompt(threat)

	// Check that prompt contains key information
	if !strings.Contains(prompt, "TEST-001") {
		t.Error("Prompt should contain alert ID")
	}

	if !strings.Contains(prompt, "Suspicious Activity") {
		t.Error("Prompt should contain threat name")
	}

	if !strings.Contains(prompt, "192.0.2.1") {
		t.Error("Prompt should contain IOC value")
	}

	if !strings.Contains(prompt, "alienvault-otx") {
		t.Error("Prompt should contain sources")
	}

	if !strings.Contains(prompt, "c2_server") {
		t.Error("Prompt should contain threat types")
	}

	// Check for guidelines
	if !strings.Contains(prompt, "Important Guidelines") {
		t.Error("Prompt should contain guidelines")
	}

	// Check for examples
	if !strings.Contains(prompt, "Example 1") {
		t.Error("Prompt should contain examples")
	}
}

func TestParseResponse(t *testing.T) {
	triager := &LLMTriager{}

	tests := []struct {
		name     string
		response string
		wantErr  bool
	}{
		{
			name: "Valid JSON in markdown",
			response: "```json\n" +
				`{"severity":"high","priority":2,"summary":"Test","analysis":"Test analysis","recommended":["Action 1"],"false_positive":false,"confidence":85}` +
				"\n```",
			wantErr: false,
		},
		{
			name:     "Valid JSON without markdown",
			response: `{"severity":"medium","priority":3,"summary":"Test","analysis":"Test","recommended":[],"false_positive":false,"confidence":70}`,
			wantErr:  false,
		},
		{
			name:     "Invalid JSON",
			response: "not a valid json",
			wantErr:  true,
		},
		{
			name: "JSON with extra text",
			response: "Here is my analysis:\n```json\n" +
				`{"severity":"low","priority":4,"summary":"Test","analysis":"Test","recommended":[],"false_positive":true,"confidence":90}` +
				"\n```\nHope this helps!",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := triager.parseResponse(tt.response)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("Expected non-nil result")
				return
			}

			// Verify result has required fields
			if result.Severity == "" {
				t.Error("Expected severity to be set")
			}

			if result.Summary == "" {
				t.Error("Expected summary to be set")
			}
		})
	}
}

func TestTriageWithMockLLM(t *testing.T) {
	// Create mock LLM server
	mockResponse := map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]string{
					"content": `{
						"severity": "medium",
						"priority": 3,
						"summary": "Suspicious activity detected",
						"analysis": "The endpoint contacted an unknown domain",
						"recommended": ["Monitor endpoint", "Investigate further"],
						"false_positive": false,
						"confidence": 70
					}`,
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("Expected Content-Type: application/json")
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Error("Expected Authorization header with Bearer token")
		}

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// Create triager with mock server
	config := ResilientClientConfig{
		EnableCircuitBreaker: false,
		MaxRetries:           0,
		InitialInterval:      100 * time.Millisecond,
		MaxInterval:          1 * time.Second,
	}
	triager := &LLMTriager{
		apiURL:  server.URL,
		apiKey:  "test-key",
		model:   "gpt-4o-mini",
		client:  NewResilientClient(5*time.Second, config),
		enabled: true,
	}

	// Use an unknown IOC that won't trigger pre-guardrails
	threat := ThreatContext{
		AlertID:        "TEST-001",
		ThreatName:     "Suspicious Activity",
		Classification: "Suspicious",
		Endpoint:       "TEST-LAPTOP",
		OSType:         "windows",
		IOCs: []IOCContext{
			{
				Type:       "DOMAIN",
				Value:      "unknown-test-domain.xyz",
				InDatabase: false, // Not in database, won't trigger pre-filter
			},
		},
	}

	ctx := context.Background()
	result, err := triager.Triage(ctx, threat)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Severity != "medium" {
		t.Errorf("Expected severity=medium, got %s", result.Severity)
	}

	if result.Confidence != 70 {
		t.Errorf("Expected confidence=70, got %d", result.Confidence)
	}

	if result.FalsePositive {
		t.Error("Expected FalsePositive=false")
	}
}

func TestTriageWithPreGuardrail(t *testing.T) {
	// Create triager (no mock needed - should skip LLM call)
	config := ResilientClientConfig{
		EnableCircuitBreaker: false,
		MaxRetries:           0,
		InitialInterval:      100 * time.Millisecond,
		MaxInterval:          1 * time.Second,
	}
	triager := &LLMTriager{
		apiURL:  "http://unused",
		apiKey:  "test-key",
		model:   "gpt-4o-mini",
		client:  NewResilientClient(5*time.Second, config),
		enabled: true,
	}

	// Known good domain - should be caught by pre-guardrail
	threat := ThreatContext{
		AlertID:        "TEST-002",
		ThreatName:     "Suspicious DNS",
		Classification: "Suspicious",
		Endpoint:       "TEST-LAPTOP",
		OSType:         "windows",
		IOCs: []IOCContext{
			{
				Type:       "DOMAIN",
				Value:      "update.microsoft.com",
				InDatabase: false,
			},
		},
	}

	ctx := context.Background()
	result, err := triager.Triage(ctx, threat)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result from pre-guardrail")
	}

	if result.Severity != "info" {
		t.Errorf("Expected severity=info for known good, got %s", result.Severity)
	}

	if !result.FalsePositive {
		t.Error("Expected FalsePositive=true for known good domain")
	}

	if result.Confidence != 95 {
		t.Errorf("Expected confidence=95, got %d", result.Confidence)
	}
}

func TestTriageDisabled(t *testing.T) {
	triager := &LLMTriager{
		enabled: false,
	}

	threat := ThreatContext{
		AlertID: "TEST-003",
	}

	ctx := context.Background()
	result, err := triager.Triage(ctx, threat)

	if err == nil {
		t.Error("Expected error when triaging is disabled")
	}

	if result != nil {
		t.Error("Expected nil result when triaging is disabled")
	}
}

func TestCallLLMTimeout(t *testing.T) {
	// Create slow server that will timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := ResilientClientConfig{
		EnableCircuitBreaker: false,
		MaxRetries:           0,
		InitialInterval:      100 * time.Millisecond,
		MaxInterval:          1 * time.Second,
	}
	triager := &LLMTriager{
		apiURL:  server.URL,
		apiKey:  "test-key",
		model:   "gpt-4o-mini",
		client:  NewResilientClient(100*time.Millisecond, config), // Short timeout
		enabled: true,
	}

	ctx := context.Background()
	_, err := triager.callLLM(ctx, "test prompt")

	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestCallLLMErrorResponse(t *testing.T) {
	// Create server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
	}))
	defer server.Close()

	config := ResilientClientConfig{
		EnableCircuitBreaker: false,
		MaxRetries:           0,
		InitialInterval:      100 * time.Millisecond,
		MaxInterval:          1 * time.Second,
	}
	triager := &LLMTriager{
		apiURL:  server.URL,
		apiKey:  "test-key",
		model:   "gpt-4o-mini",
		client:  NewResilientClient(5*time.Second, config),
		enabled: true,
	}

	ctx := context.Background()
	_, err := triager.callLLM(ctx, "test prompt")

	if err == nil {
		t.Error("Expected error for 500 status code")
	}

	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Expected error message to contain status code, got: %v", err)
	}
}

func TestNewLLMTriager(t *testing.T) {
	// Save original env
	originalEnabled := ""
	originalAPIKey := ""

	// Test with enabled=false
	t.Setenv("LLM_TRIAGE_ENABLED", "false")
	t.Setenv("LLM_API_KEY", "")

	triager := NewLLMTriager()

	if triager.IsEnabled() {
		t.Error("Expected IsEnabled=false when not configured")
	}

	// Test with enabled=true but no API key
	t.Setenv("LLM_TRIAGE_ENABLED", "true")
	t.Setenv("LLM_API_KEY", "")

	triager = NewLLMTriager()

	if triager.IsEnabled() {
		t.Error("Expected IsEnabled=false when API key is missing")
	}

	// Test with enabled=true and API key
	t.Setenv("LLM_TRIAGE_ENABLED", "true")
	t.Setenv("LLM_API_KEY", "test-key")

	triager = NewLLMTriager()

	if !triager.IsEnabled() {
		t.Error("Expected IsEnabled=true when properly configured")
	}

	// Restore env
	if originalEnabled != "" {
		t.Setenv("LLM_TRIAGE_ENABLED", originalEnabled)
	}
	if originalAPIKey != "" {
		t.Setenv("LLM_API_KEY", originalAPIKey)
	}
}

func BenchmarkBuildPrompt(b *testing.B) {
	triager := &LLMTriager{}

	threat := ThreatContext{
		AlertID:        "BENCH-001",
		ThreatName:     "Test",
		Classification: "Test",
		Endpoint:       "TEST",
		OSType:         "linux",
		IOCs: []IOCContext{
			{
				Type:        "IPV4",
				Value:       "192.0.2.1",
				InDatabase:  true,
				Sources:     []string{"test1", "test2"},
				ThreatTypes: []string{"c2_server"},
				Tags:        []string{"tag1", "tag2"},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		triager.buildPrompt(threat)
	}
}

func BenchmarkParseResponse(b *testing.B) {
	triager := &LLMTriager{}

	response := `{"severity":"high","priority":2,"summary":"Test","analysis":"Test analysis","recommended":["Action 1","Action 2"],"false_positive":false,"confidence":85}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		triager.parseResponse(response)
	}
}
