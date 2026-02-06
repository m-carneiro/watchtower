package llm

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// metricsOnce ensures metrics are registered only once
	metricsOnce sync.Once

	// llmTriageRequestsTotal tracks total triage requests by status and reason
	llmTriageRequestsTotal *prometheus.CounterVec

	// llmTriageDuration tracks latency of triage operations
	llmTriageDuration prometheus.Histogram

	// llmTriageGuardrailsTotal tracks guardrail activations
	llmTriageGuardrailsTotal *prometheus.CounterVec

	// llmAPIErrorsTotal tracks LLM API errors by type
	llmAPIErrorsTotal *prometheus.CounterVec

	// llmTriageConfidence tracks distribution of confidence scores
	llmTriageConfidence prometheus.Histogram

	// llmTriageSeverity tracks distribution of severity levels
	llmTriageSeverity *prometheus.CounterVec

	// llmFalsePositiveRate tracks percentage of alerts marked as false positive
	llmFalsePositiveRate prometheus.Gauge
)

// InitMetrics registers all Prometheus metrics for LLM triaging
// This should be called once at application startup
func InitMetrics() {
	metricsOnce.Do(func() {
		llmTriageRequestsTotal = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "llm_triage_requests_total",
				Help: "Total number of LLM triage requests by status and reason",
			},
			[]string{"status", "reason"},
		)

		llmTriageDuration = promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "llm_triage_duration_seconds",
				Help:    "Duration of LLM triage operations in seconds",
				Buckets: []float64{0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0},
			},
		)

		llmTriageGuardrailsTotal = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "llm_triage_guardrails_total",
				Help: "Total number of guardrail activations by type and action",
			},
			[]string{"type", "action"},
		)

		llmAPIErrorsTotal = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "llm_api_errors_total",
				Help: "Total number of LLM API errors by error type",
			},
			[]string{"error_type"},
		)

		llmTriageConfidence = promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "llm_triage_confidence",
				Help:    "Distribution of LLM triage confidence scores (0-100)",
				Buckets: []float64{50, 60, 70, 75, 80, 85, 90, 95, 100},
			},
		)

		llmTriageSeverity = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "llm_triage_severity",
				Help: "Distribution of triage severity levels",
			},
			[]string{"severity"},
		)

		llmFalsePositiveRate = promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "llm_false_positive_rate",
				Help: "Percentage of alerts marked as false positive",
			},
		)
	})
}

// RecordTriageRequest records a triage request with status and reason
// status: "success", "error", "skipped"
// reason: "pre_filter", "llm", "error", "timeout", etc.
func RecordTriageRequest(status, reason string) {
	if llmTriageRequestsTotal != nil {
		llmTriageRequestsTotal.WithLabelValues(status, reason).Inc()
	}
}

// RecordTriageDuration records the duration of a triage operation
func RecordTriageDuration(duration time.Duration) {
	if llmTriageDuration != nil {
		llmTriageDuration.Observe(duration.Seconds())
	}
}

// RecordGuardrail records a guardrail activation
// guardType: "pre", "post"
// action: "skip", "override", "boost", "downgrade"
func RecordGuardrail(guardType, action string) {
	if llmTriageGuardrailsTotal != nil {
		llmTriageGuardrailsTotal.WithLabelValues(guardType, action).Inc()
	}
}

// RecordError records an LLM API error by type
// errorType: "timeout", "auth", "rate_limit", "server_error", "connection", "parse", "circuit_open"
func RecordError(errorType string) {
	if llmAPIErrorsTotal != nil {
		llmAPIErrorsTotal.WithLabelValues(errorType).Inc()
	}
}

// RecordResult records metrics from a completed triage result
func RecordResult(result *TriageResult) {
	if result == nil {
		return
	}

	// Record confidence score
	if llmTriageConfidence != nil {
		llmTriageConfidence.Observe(float64(result.Confidence))
	}

	// Record severity
	if llmTriageSeverity != nil {
		llmTriageSeverity.WithLabelValues(result.Severity).Inc()
	}

	// Note: False positive rate is calculated separately as it requires
	// tracking total alerts vs FP alerts over a time window
	// For now, we track individual FP results via the request counter
}

// RecordFalsePositive records when an alert is marked as a false positive
func RecordFalsePositive() {
	// This increments a counter that can be used to calculate FP rate
	if llmTriageRequestsTotal != nil {
		llmTriageRequestsTotal.WithLabelValues("success", "false_positive").Inc()
	}
}

// UpdateFalsePositiveRate updates the false positive rate gauge
// This should be called periodically (e.g., every minute) to calculate
// the FP rate over a sliding window
func UpdateFalsePositiveRate(rate float64) {
	if llmFalsePositiveRate != nil {
		llmFalsePositiveRate.Set(rate)
	}
}

// TriageTimer is a helper for timing triage operations
type TriageTimer struct {
	start time.Time
}

// StartTimer creates a new timer for measuring triage duration
func StartTimer() *TriageTimer {
	return &TriageTimer{start: time.Now()}
}

// ObserveDuration records the elapsed time since the timer started
func (t *TriageTimer) ObserveDuration() {
	if t != nil {
		RecordTriageDuration(time.Since(t.start))
	}
}
