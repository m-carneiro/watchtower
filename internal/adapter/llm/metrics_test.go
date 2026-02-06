package llm

import (
	"testing"
	"time"
)

func TestInitMetrics(t *testing.T) {
	// Should not panic when called
	InitMetrics()

	// Should be idempotent (safe to call multiple times)
	InitMetrics()
	InitMetrics()
}

func TestRecordTriageRequest(t *testing.T) {
	InitMetrics()

	tests := []struct {
		status string
		reason string
	}{
		{"success", "llm"},
		{"success", "pre_filter"},
		{"skipped", "pre_filter"},
		{"error", "timeout"},
		{"error", "circuit_open"},
	}

	for _, tt := range tests {
		t.Run(tt.status+"_"+tt.reason, func(t *testing.T) {
			// Should not panic
			RecordTriageRequest(tt.status, tt.reason)
		})
	}
}

func TestRecordTriageDuration(t *testing.T) {
	InitMetrics()

	tests := []time.Duration{
		100 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		2 * time.Second,
	}

	for _, duration := range tests {
		t.Run(duration.String(), func(t *testing.T) {
			// Should not panic
			RecordTriageDuration(duration)
		})
	}
}

func TestRecordGuardrail(t *testing.T) {
	InitMetrics()

	tests := []struct {
		guardType string
		action    string
	}{
		{"pre", "skip"},
		{"post", "override"},
		{"post", "boost"},
		{"post", "downgrade"},
	}

	for _, tt := range tests {
		t.Run(tt.guardType+"_"+tt.action, func(t *testing.T) {
			// Should not panic
			RecordGuardrail(tt.guardType, tt.action)
		})
	}
}

func TestRecordError(t *testing.T) {
	InitMetrics()

	errorTypes := []string{
		"timeout",
		"auth",
		"rate_limit",
		"server_error",
		"connection",
		"parse",
		"circuit_open",
	}

	for _, errorType := range errorTypes {
		t.Run(errorType, func(t *testing.T) {
			// Should not panic
			RecordError(errorType)
		})
	}
}

func TestRecordResult(t *testing.T) {
	InitMetrics()

	tests := []struct {
		name   string
		result *TriageResult
	}{
		{
			name: "high_severity",
			result: &TriageResult{
				Severity:      "high",
				Confidence:    90,
				FalsePositive: false,
			},
		},
		{
			name: "false_positive",
			result: &TriageResult{
				Severity:      "info",
				Confidence:    95,
				FalsePositive: true,
			},
		},
		{
			name:   "nil_result",
			result: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			RecordResult(tt.result)
		})
	}
}

func TestRecordFalsePositive(t *testing.T) {
	InitMetrics()

	// Should not panic
	RecordFalsePositive()
	RecordFalsePositive()
}

func TestUpdateFalsePositiveRate(t *testing.T) {
	InitMetrics()

	rates := []float64{0.0, 0.05, 0.15, 0.25, 0.5, 0.75, 1.0}

	for _, rate := range rates {
		t.Run("rate", func(t *testing.T) {
			// Should not panic
			UpdateFalsePositiveRate(rate)
		})
	}
}

func TestTriageTimer(t *testing.T) {
	InitMetrics()

	timer := StartTimer()
	if timer == nil {
		t.Fatal("StartTimer returned nil")
	}

	// Simulate some work
	time.Sleep(10 * time.Millisecond)

	// Should not panic
	timer.ObserveDuration()

	// Should be safe to call multiple times
	timer.ObserveDuration()

	// Should handle nil timer
	var nilTimer *TriageTimer
	nilTimer.ObserveDuration() // Should not panic
}
