package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hive-corporation/watchtower/internal/adapter/handler"
	"github.com/hive-corporation/watchtower/internal/adapter/llm"
	"github.com/hive-corporation/watchtower/internal/core/domain"
)

// Mock repository for testing
type mockRepository struct {
	iocs map[string]*domain.IOC
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		iocs: make(map[string]*domain.IOC),
	}
}

func (m *mockRepository) FindByValue(ctx context.Context, value string) (*domain.IOC, error) {
	if ioc, exists := m.iocs[value]; exists {
		return ioc, nil
	}
	return nil, nil
}

func (m *mockRepository) FindAllByValue(ctx context.Context, value string) ([]domain.IOC, error) {
	var results []domain.IOC
	if ioc, exists := m.iocs[value]; exists {
		results = append(results, *ioc)
	}
	return results, nil
}

func (m *mockRepository) FindByValueAndVersion(ctx context.Context, value, version string) ([]domain.IOC, error) {
	var results []domain.IOC
	if ioc, exists := m.iocs[value]; exists {
		if ioc.Version == version || version == "" {
			results = append(results, *ioc)
		}
	}
	return results, nil
}

func (m *mockRepository) FindContaining(ctx context.Context, value string) ([]domain.IOC, error) {
	var results []domain.IOC
	for _, ioc := range m.iocs {
		if ioc.Value == value {
			results = append(results, *ioc)
		}
	}
	return results, nil
}

func (m *mockRepository) SaveBatch(ctx context.Context, iocs []domain.IOC) error {
	for i := range iocs {
		m.iocs[iocs[i].Value] = &iocs[i]
	}
	return nil
}

func (m *mockRepository) FindSince(ctx context.Context, since time.Time, limit int) ([]domain.IOC, error) {
	var results []domain.IOC
	count := 0
	for _, ioc := range m.iocs {
		if ioc.DateIngested.After(since) {
			results = append(results, *ioc)
			count++
			if limit > 0 && count >= limit {
				break
			}
		}
	}
	return results, nil
}

// Mock LLM server
func createMockLLMServer(t *testing.T, responseFunc func(*http.Request) map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := responseFunc(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
}

func TestE2E_KnownGoodDomain_SkipsLLM(t *testing.T) {
	repo := newMockRepository()

	// Create mock LLM server that should NOT be called
	llmCalled := false
	mockLLM := createMockLLMServer(t, func(r *http.Request) map[string]interface{} {
		llmCalled = true
		t.Error("LLM should not be called for known good domain")
		return nil
	})
	defer mockLLM.Close()

	// Configure LLM triager with mock server
	t.Setenv("LLM_TRIAGE_ENABLED", "true")
	t.Setenv("LLM_API_KEY", "test-key")
	t.Setenv("LLM_API_URL", mockLLM.URL)

	triager := llm.NewLLMTriager()
	restHandler := handler.NewRestHandler(repo, nil, triager)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/webhooks/sentinelone", restHandler.SentinelOneWebhook).Methods("POST")

	// Create request with known good domain
	payload := map[string]interface{}{
		"alertId":        "test-e2e-001",
		"threatName":     "Suspicious DNS Query",
		"classification": "Suspicious",
		"indicators": []map[string]string{
			{"type": "DOMAIN", "value": "update.microsoft.com"},
		},
		"endpoint": map[string]string{
			"computerName": "TEST-LAPTOP",
			"osType":       "windows",
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/sentinelone", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["status"] != "received" {
		t.Errorf("Expected status=received, got %v", response["status"])
	}

	// Verify LLM was NOT called
	if llmCalled {
		t.Error("LLM should have been skipped by pre-guardrail")
	}
}

func TestE2E_HighRiskIOC_SkipsLLM(t *testing.T) {
	repo := newMockRepository()

	// Add high-risk IOC to mock database
	repo.iocs["192.0.2.100"] = &domain.IOC{
		Value:        "192.0.2.100",
		Type:         domain.IPAddress,
		Source:       "alienvault-otx",
		ThreatType:   "c2_server",
		Tags:         []string{"malware", "c2", "botnet"},
		FirstSeen:    time.Now().Add(-24 * time.Hour),
		DateIngested: time.Now(),
	}

	// Create mock LLM server that should NOT be called
	llmCalled := false
	mockLLM := createMockLLMServer(t, func(r *http.Request) map[string]interface{} {
		llmCalled = true
		t.Error("LLM should not be called for high-risk IOC")
		return nil
	})
	defer mockLLM.Close()

	// Configure LLM triager
	t.Setenv("LLM_TRIAGE_ENABLED", "true")
	t.Setenv("LLM_API_KEY", "test-key")
	t.Setenv("LLM_API_URL", mockLLM.URL)

	triager := llm.NewLLMTriager()
	restHandler := handler.NewRestHandler(repo, nil, triager)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/webhooks/sentinelone", restHandler.SentinelOneWebhook).Methods("POST")

	// Create request with high-risk IOC
	payload := map[string]interface{}{
		"alertId":        "test-e2e-002",
		"threatName":     "C2 Communication",
		"classification": "Malware",
		"indicators": []map[string]string{
			{"type": "IPV4", "value": "192.0.2.100"},
		},
		"endpoint": map[string]string{
			"computerName": "SERVER-01",
			"osType":       "linux",
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/sentinelone", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["indicators_in_db"].(float64) != 1 {
		t.Errorf("Expected 1 indicator in DB, got %v", response["indicators_in_db"])
	}

	// Verify LLM was NOT called
	if llmCalled {
		t.Error("LLM should have been skipped by pre-guardrail")
	}
}

func TestE2E_UnknownIOC_CallsLLMWithValidation(t *testing.T) {
	repo := newMockRepository()

	// Create mock LLM server with incorrect response (will be corrected by guardrails)
	mockLLM := createMockLLMServer(t, func(r *http.Request) map[string]interface{} {
		// LLM incorrectly marks as low severity
		return map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"content": `{
							"severity": "low",
							"priority": 4,
							"summary": "Unknown activity",
							"analysis": "No threat intelligence available",
							"recommended": ["Monitor endpoint"],
							"false_positive": false,
							"confidence": 60
						}`,
					},
				},
			},
		}
	})
	defer mockLLM.Close()

	// Configure LLM triager
	t.Setenv("LLM_TRIAGE_ENABLED", "true")
	t.Setenv("LLM_API_KEY", "test-key")
	t.Setenv("LLM_API_URL", mockLLM.URL)

	triager := llm.NewLLMTriager()
	restHandler := handler.NewRestHandler(repo, nil, triager)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/webhooks/sentinelone", restHandler.SentinelOneWebhook).Methods("POST")

	// Create request with unknown IOC
	payload := map[string]interface{}{
		"alertId":        "test-e2e-003",
		"threatName":     "Suspicious Activity",
		"classification": "Suspicious",
		"indicators": []map[string]string{
			{"type": "DOMAIN", "value": "unknown-test-domain.xyz"},
		},
		"endpoint": map[string]string{
			"computerName": "WORKSTATION-10",
			"osType":       "windows",
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/sentinelone", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["status"] != "received" {
		t.Errorf("Expected status=received, got %v", response["status"])
	}

	// Verify LLM triaging occurred
	if _, exists := response["llm_triaged"]; !exists {
		t.Error("Expected llm_triaged field in response")
	}
}

func TestE2E_LLMDisabled_FallbackBehavior(t *testing.T) {
	repo := newMockRepository()

	// Disable LLM triaging
	t.Setenv("LLM_TRIAGE_ENABLED", "false")
	t.Setenv("LLM_API_KEY", "")

	triager := llm.NewLLMTriager()
	restHandler := handler.NewRestHandler(repo, nil, triager)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/webhooks/sentinelone", restHandler.SentinelOneWebhook).Methods("POST")

	// Create request
	payload := map[string]interface{}{
		"alertId":        "test-e2e-004",
		"threatName":     "Test",
		"classification": "Test",
		"indicators": []map[string]string{
			{"type": "DOMAIN", "value": "test.com"},
		},
		"endpoint": map[string]string{
			"computerName": "TEST",
			"osType":       "linux",
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/sentinelone", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	// Should have llm_triaged=false when disabled
	if llmTriaged, exists := response["llm_triaged"]; !exists {
		t.Error("Expected llm_triaged field in response")
	} else if llmTriaged.(bool) != false {
		t.Errorf("Expected llm_triaged=false when disabled, got %v", llmTriaged)
	}
}

func TestE2E_ErrorHandling_InvalidJSON(t *testing.T) {
	repo := newMockRepository()
	triager := llm.NewLLMTriager()
	restHandler := handler.NewRestHandler(repo, nil, triager)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/webhooks/sentinelone", restHandler.SentinelOneWebhook).Methods("POST")

	// Send invalid JSON
	req := httptest.NewRequest("POST", "/api/v1/webhooks/sentinelone", bytes.NewBufferString("{invalid}"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify error response
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if _, exists := response["error"]; !exists {
		t.Error("Expected error field in response")
	}
}

func TestE2E_ErrorHandling_MissingFields(t *testing.T) {
	repo := newMockRepository()
	triager := llm.NewLLMTriager()
	restHandler := handler.NewRestHandler(repo, nil, triager)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/webhooks/sentinelone", restHandler.SentinelOneWebhook).Methods("POST")

	// Send payload with missing required fields
	payload := map[string]interface{}{
		"alertId": "test-e2e-005",
		// Missing other required fields
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/sentinelone", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should still return 200 (graceful handling)
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 200 or 400, got %d", w.Code)
	}
}

func BenchmarkE2E_PreGuardrailPath(b *testing.B) {
	repo := newMockRepository()

	b.Setenv("LLM_TRIAGE_ENABLED", "true")
	b.Setenv("LLM_API_KEY", "test-key")

	triager := llm.NewLLMTriager()
	restHandler := handler.NewRestHandler(repo, nil, triager)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/webhooks/sentinelone", restHandler.SentinelOneWebhook).Methods("POST")

	payload := map[string]interface{}{
		"alertId":        "bench-001",
		"threatName":     "Test",
		"classification": "Test",
		"indicators": []map[string]string{
			{"type": "DOMAIN", "value": "update.microsoft.com"},
		},
		"endpoint": map[string]string{
			"computerName": "TEST",
			"osType":       "windows",
		},
	}

	body, _ := json.Marshal(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/v1/webhooks/sentinelone", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
