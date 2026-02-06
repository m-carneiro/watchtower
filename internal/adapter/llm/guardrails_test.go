package llm

import (
	"testing"
)

func TestIsKnownGoodIndicator(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"Microsoft domain", "update.microsoft.com", true},
		{"Microsoft subdomain", "windowsupdate.com", true},
		{"AWS domain", "s3.amazonaws.com", true},
		{"Google domain", "fonts.googleapis.com", true},
		{"CloudFlare CDN", "cdnjs.cloudflare.com", true},
		{"Unknown domain", "malicious-site.xyz", false},
		{"IP address", "192.0.2.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isKnownGoodIndicator(tt.value)
			if result != tt.expected {
				t.Errorf("isKnownGoodIndicator(%q) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}

func TestIsHighRiskThreatType(t *testing.T) {
	tests := []struct {
		name       string
		threatType string
		expected   bool
	}{
		{"C2 server", "c2_server", true},
		{"Command and control", "command_and_control", true},
		{"Botnet", "botnet", true},
		{"Ransomware", "ransomware", true},
		{"Malware download", "malware_download", true},
		{"Phishing", "phishing", true},
		{"Generic suspicious", "suspicious", false},
		{"Scanner", "scanner", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isHighRiskThreatType(tt.threatType)
			if result != tt.expected {
				t.Errorf("isHighRiskThreatType(%q) = %v, want %v", tt.threatType, result, tt.expected)
			}
		})
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected string
	}{
		{"Valid critical", "critical", "critical"},
		{"Valid high", "high", "high"},
		{"Valid medium", "medium", "medium"},
		{"Valid low", "low", "low"},
		{"Valid info", "info", "info"},
		{"Uppercase", "HIGH", "high"},
		{"With spaces", " medium ", "medium"},
		{"Invalid", "unknown", "medium"},
		{"Empty", "", "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeSeverity(tt.severity)
			if result != tt.expected {
				t.Errorf("normalizeSeverity(%q) = %v, want %v", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestNormalizeConfidence(t *testing.T) {
	tests := []struct {
		name       string
		confidence int
		expected   int
	}{
		{"Valid 50", 50, 50},
		{"Valid 85", 85, 85},
		{"Valid 100", 100, 100},
		{"Too low", -10, 0},
		{"Too high", 150, 100},
		{"Zero", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeConfidence(tt.confidence)
			if result != tt.expected {
				t.Errorf("normalizeConfidence(%d) = %v, want %v", tt.confidence, result, tt.expected)
			}
		})
	}
}

func TestApplyPreLLMGuardrails_AllKnownGood(t *testing.T) {
	threat := ThreatContext{
		AlertID:        "test-001",
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

	config := DefaultGuardrailConfig()
	result, shouldSkip := ApplyPreLLMGuardrails(threat, config)

	if !shouldSkip {
		t.Error("Expected shouldSkip=true for known good domain")
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Severity != "info" {
		t.Errorf("Expected severity=info, got %s", result.Severity)
	}

	if !result.FalsePositive {
		t.Error("Expected FalsePositive=true")
	}

	if result.Confidence != 95 {
		t.Errorf("Expected confidence=95, got %d", result.Confidence)
	}
}

func TestApplyPreLLMGuardrails_HighRiskThreatType(t *testing.T) {
	threat := ThreatContext{
		AlertID:        "test-002",
		ThreatName:     "C2 Communication",
		Classification: "Malware",
		Endpoint:       "SERVER-01",
		OSType:         "linux",
		IOCs: []IOCContext{
			{
				Type:        "IPV4",
				Value:       "192.0.2.1",
				InDatabase:  true,
				Sources:     []string{"alienvault-otx", "urlhaus"},
				ThreatTypes: []string{"c2_server", "botnet"},
			},
		},
	}

	config := DefaultGuardrailConfig()
	result, shouldSkip := ApplyPreLLMGuardrails(threat, config)

	if !shouldSkip {
		t.Error("Expected shouldSkip=true for high-risk threat type")
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Severity != "high" {
		t.Errorf("Expected severity=high, got %s", result.Severity)
	}

	if result.FalsePositive {
		t.Error("Expected FalsePositive=false")
	}

	if result.Confidence != 90 {
		t.Errorf("Expected confidence=90, got %d", result.Confidence)
	}
}

func TestApplyPreLLMGuardrails_NoMatch(t *testing.T) {
	threat := ThreatContext{
		AlertID:        "test-003",
		ThreatName:     "Suspicious Activity",
		Classification: "Suspicious",
		Endpoint:       "WORKSTATION-10",
		OSType:         "windows",
		IOCs: []IOCContext{
			{
				Type:       "DOMAIN",
				Value:      "unknown-domain.xyz",
				InDatabase: false,
			},
		},
	}

	config := DefaultGuardrailConfig()
	result, shouldSkip := ApplyPreLLMGuardrails(threat, config)

	if shouldSkip {
		t.Error("Expected shouldSkip=false for unknown domain")
	}

	if result != nil {
		t.Error("Expected nil result when no pre-filter matches")
	}
}

func TestApplyPostLLMGuardrails_OverrideFalsePositive(t *testing.T) {
	// LLM incorrectly marks as false positive but IOC is in database
	result := &TriageResult{
		Severity:      "info",
		Priority:      5,
		FalsePositive: true,
		Confidence:    70,
	}

	threat := ThreatContext{
		AlertID: "test-004",
		IOCs: []IOCContext{
			{
				Type:       "IPV4",
				Value:      "192.0.2.1",
				InDatabase: true,
				Sources:    []string{"alienvault-otx"},
			},
		},
	}

	config := DefaultGuardrailConfig()
	adjusted := ApplyPostLLMGuardrails(result, threat, config)

	if adjusted.FalsePositive {
		t.Error("Expected FalsePositive to be overridden to false")
	}

	if adjusted.Severity == "info" {
		t.Error("Expected severity to be upgraded from info")
	}

	if adjusted.Confidence >= 70 {
		t.Error("Expected confidence to be reduced due to inconsistency")
	}
}

func TestApplyPostLLMGuardrails_UpgradeSeverity(t *testing.T) {
	// LLM marks as low severity but has high-risk threat types
	result := &TriageResult{
		Severity:      "low",
		Priority:      4,
		FalsePositive: false,
		Confidence:    70,
	}

	threat := ThreatContext{
		AlertID: "test-005",
		IOCs: []IOCContext{
			{
				Type:        "IPV4",
				Value:       "192.0.2.1",
				InDatabase:  true,
				ThreatTypes: []string{"c2_server", "ransomware"},
			},
		},
	}

	config := DefaultGuardrailConfig()
	adjusted := ApplyPostLLMGuardrails(result, threat, config)

	if adjusted.Severity != "high" {
		t.Errorf("Expected severity to be upgraded to high, got %s", adjusted.Severity)
	}

	if adjusted.Priority != 2 {
		t.Errorf("Expected priority=2, got %d", adjusted.Priority)
	}

	if adjusted.Confidence < 70 {
		t.Error("Expected confidence to be boosted")
	}
}

func TestApplyPostLLMGuardrails_BoostConfidence(t *testing.T) {
	result := &TriageResult{
		Severity:      "high",
		Priority:      2,
		FalsePositive: false,
		Confidence:    70,
	}

	threat := ThreatContext{
		AlertID: "test-006",
		IOCs: []IOCContext{
			{
				Type:       "IPV4",
				Value:      "192.0.2.1",
				InDatabase: true,
				Sources:    []string{"alienvault-otx", "urlhaus", "abuse.ch", "digitalside"},
			},
		},
	}

	config := DefaultGuardrailConfig()
	adjusted := ApplyPostLLMGuardrails(result, threat, config)

	if adjusted.Confidence <= 70 {
		t.Errorf("Expected confidence to be boosted, got %d", adjusted.Confidence)
	}
}

func TestApplyPostLLMGuardrails_RequireThreatIntelForCritical(t *testing.T) {
	result := &TriageResult{
		Severity:      "critical",
		Priority:      1,
		FalsePositive: false,
		Confidence:    85,
	}

	threat := ThreatContext{
		AlertID: "test-007",
		IOCs: []IOCContext{
			{
				Type:       "DOMAIN",
				Value:      "unknown-domain.xyz",
				InDatabase: false,
			},
		},
	}

	config := DefaultGuardrailConfig()
	adjusted := ApplyPostLLMGuardrails(result, threat, config)

	if adjusted.Severity == "critical" {
		t.Error("Expected critical to be downgraded without threat intel")
	}

	if adjusted.Confidence >= 85 {
		t.Error("Expected confidence to be reduced")
	}
}

func TestApplyPostLLMGuardrails_LowConfidenceFalsePositive(t *testing.T) {
	result := &TriageResult{
		Severity:      "info",
		Priority:      5,
		FalsePositive: true,
		Confidence:    70, // Below threshold of 85
	}

	threat := ThreatContext{
		AlertID: "test-008",
		IOCs:    []IOCContext{},
	}

	config := DefaultGuardrailConfig()
	adjusted := ApplyPostLLMGuardrails(result, threat, config)

	if adjusted.FalsePositive {
		t.Error("Expected FalsePositive to be overridden due to low confidence")
	}

	if adjusted.Severity != "low" {
		t.Errorf("Expected severity=low for uncertain case, got %s", adjusted.Severity)
	}
}

func TestEnsurePriorityMatchesSeverity(t *testing.T) {
	tests := []struct {
		name             string
		priority         int
		severity         string
		expectedPriority int
	}{
		{"Critical matches P1", 1, "critical", 1},
		{"High matches P2", 2, "high", 2},
		{"Medium matches P3", 3, "medium", 3},
		{"Low matches P4", 4, "low", 4},
		{"Info matches P5", 5, "info", 5},
		{"Critical with P3 adjusted", 3, "critical", 1},
		{"High with P5 adjusted", 5, "high", 2},
		{"Allow P2 for critical", 2, "critical", 2}, // Within ±1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ensurePriorityMatchesSeverity(tt.priority, tt.severity)
			if result != tt.expectedPriority {
				t.Errorf("ensurePriorityMatchesSeverity(%d, %q) = %d, want %d",
					tt.priority, tt.severity, result, tt.expectedPriority)
			}
		})
	}
}

func TestGetDefaultRecommendations(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		minLen   int
	}{
		{"Critical recommendations", "critical", 3},
		{"High recommendations", "high", 3},
		{"Medium recommendations", "medium", 2},
		{"Low recommendations", "low", 1},
		{"Info recommendations", "info", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDefaultRecommendations(tt.severity)
			if len(result) < tt.minLen {
				t.Errorf("Expected at least %d recommendations, got %d", tt.minLen, len(result))
			}
		})
	}
}

func TestApplyPostLLMGuardrails_AddDefaultRecommendations(t *testing.T) {
	result := &TriageResult{
		Severity:      "high",
		Priority:      2,
		FalsePositive: false,
		Confidence:    85,
		Recommended:   []string{}, // Empty recommendations
	}

	threat := ThreatContext{
		AlertID: "test-009",
		IOCs: []IOCContext{
			{
				Type:       "IPV4",
				Value:      "192.0.2.1",
				InDatabase: true,
			},
		},
	}

	config := DefaultGuardrailConfig()
	adjusted := ApplyPostLLMGuardrails(result, threat, config)

	if len(adjusted.Recommended) == 0 {
		t.Error("Expected default recommendations to be added")
	}
}

func BenchmarkApplyPreLLMGuardrails(b *testing.B) {
	threat := ThreatContext{
		AlertID:        "bench-001",
		ThreatName:     "Test",
		Classification: "Test",
		Endpoint:       "TEST",
		OSType:         "linux",
		IOCs: []IOCContext{
			{
				Type:       "DOMAIN",
				Value:      "unknown-domain.xyz",
				InDatabase: false,
			},
		},
	}

	config := DefaultGuardrailConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ApplyPreLLMGuardrails(threat, config)
	}
}

func BenchmarkApplyPostLLMGuardrails(b *testing.B) {
	result := &TriageResult{
		Severity:      "medium",
		Priority:      3,
		FalsePositive: false,
		Confidence:    70,
	}

	threat := ThreatContext{
		AlertID: "bench-002",
		IOCs: []IOCContext{
			{
				Type:       "IPV4",
				Value:      "192.0.2.1",
				InDatabase: true,
				Sources:    []string{"test"},
			},
		},
	}

	config := DefaultGuardrailConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ApplyPostLLMGuardrails(result, threat, config)
	}
}
