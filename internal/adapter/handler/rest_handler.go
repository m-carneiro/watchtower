package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/hive-corporation/watchtower/internal/adapter/exporter"
	"github.com/hive-corporation/watchtower/internal/adapter/llm"
	"github.com/hive-corporation/watchtower/internal/adapter/notifier"
	"github.com/hive-corporation/watchtower/internal/core/domain"
	"github.com/hive-corporation/watchtower/internal/core/ports"
)

type RestHandler struct {
	repo          ports.IOCRepository
	slackNotifier *notifier.SlackNotifier
	cefExporter   *exporter.CEFExporter
	stixExporter  *exporter.STIXExporter
	llmTriager    *llm.LLMTriager
}

func NewRestHandler(repo ports.IOCRepository, slackNotifier *notifier.SlackNotifier, llmTriager *llm.LLMTriager) *RestHandler {
	return &RestHandler{
		repo:          repo,
		slackNotifier: slackNotifier,
		cefExporter:   exporter.NewCEFExporter(repo),
		stixExporter:  exporter.NewSTIXExporter(repo),
		llmTriager:    llmTriager,
	}
}

// Health check endpoint
func (h *RestHandler) Health(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "watchtower-api",
	}
	writeJSON(w, http.StatusOK, response)
}

// CheckIOC - REST version of gRPC CheckIOC
func (h *RestHandler) CheckIOC(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("value")
	if value == "" {
		writeError(w, http.StatusBadRequest, "missing 'value' parameter")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ioc, err := h.repo.FindByValue(ctx, value)
	if err != nil {
		// Not found - IOC is not in database
		response := map[string]interface{}{
			"exists": false,
			"value":  value,
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	// Found - return IOC details
	response := map[string]interface{}{
		"exists":        true,
		"value":         ioc.Value,
		"type":          ioc.Type,
		"source":        ioc.Source,
		"threat_type":   ioc.ThreatType,
		"tags":          ioc.Tags,
		"version":       ioc.Version,
		"first_seen":    ioc.FirstSeen.Format(time.RFC3339),
		"date_ingested": ioc.DateIngested.Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, response)
}

// SearchIOC - REST version of gRPC SearchIOC
func (h *RestHandler) SearchIOC(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("value")
	if value == "" {
		writeError(w, http.StatusBadRequest, "missing 'value' parameter")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Parse package@version format
	pkgName, version := parsePackageVersion(value)

	var iocList []domain.IOC
	var err error

	if version != "" {
		// Version-specific query
		iocList, err = h.repo.FindByValueAndVersion(ctx, pkgName, version)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to query IOCs")
			return
		}
	} else {
		// No version: return all versions
		iocList, err = h.repo.FindAllByValue(ctx, pkgName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to query IOCs")
			return
		}
	}

	// Convert IOCs to JSON-friendly format
	sightings := make([]map[string]interface{}, len(iocList))
	for i, ioc := range iocList {
		sightings[i] = map[string]interface{}{
			"value":         ioc.Value,
			"type":          string(ioc.Type),
			"source":        ioc.Source,
			"threat_type":   ioc.ThreatType,
			"tags":          ioc.Tags,
			"version":       ioc.Version,
			"first_seen":    ioc.FirstSeen.Format(time.RFC3339),
			"date_ingested": ioc.DateIngested.Format(time.RFC3339),
		}
	}

	response := map[string]interface{}{
		"value":     value,
		"count":     len(iocList),
		"sightings": sightings,
	}
	writeJSON(w, http.StatusOK, response)
}

// GetIOCFeed - Export IOCs for SIEM ingestion
func (h *RestHandler) GetIOCFeed(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	since := r.URL.Query().Get("since") // e.g., "24h", "7d"

	// Parse time duration
	var sinceTime time.Time
	if since != "" {
		duration, err := time.ParseDuration(since)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'since' parameter (use format like '24h', '7d')")
			return
		}
		sinceTime = time.Now().Add(-duration)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	switch format {
	case "cef":
		data, err := h.cefExporter.Export(ctx, sinceTime)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to export CEF feed")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(data)); err != nil {
			log.Printf("Error writing CEF feed response: %v", err)
		}

	case "stix":
		data, err := h.stixExporter.Export(ctx, sinceTime)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to export STIX feed")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(data)); err != nil {
			log.Printf("Error writing STIX feed response: %v", err)
		}

	case "json", "":
		// Default: raw JSON format
		// TODO: Implement JSON feed export
		writeError(w, http.StatusNotImplemented, "JSON format not yet implemented")

	default:
		writeError(w, http.StatusBadRequest, "unsupported format (use 'cef', 'stix', or 'json')")
	}
}

// SentinelOneWebhook - Receive alerts from SentinelOne
func (h *RestHandler) SentinelOneWebhook(w http.ResponseWriter, r *http.Request) {
	var payload SentinelOneAlert
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("❌ Failed to decode SentinelOne webhook: %v", err)
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	log.Printf("📥 Received SentinelOne alert: %s (endpoint: %s)", payload.AlertID, payload.Endpoint.ComputerName)

	// Enrich each indicator with Watchtower intelligence
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	enrichedIndicators := []EnrichedIndicator{}

	for _, indicator := range payload.Indicators {
		// Try exact match first
		iocs, err := h.repo.FindAllByValue(ctx, indicator.Value)
		if err != nil {
			log.Printf("⚠️  Failed to query IOC %s: %v", indicator.Value, err)
			continue
		}

		// If exact match fails, try "contains" search
		// This handles cases like searching for "198.0.2.12" when DB has "http://198.0.2.12/malware.sh"
		if len(iocs) == 0 {
			log.Printf("🔍 Exact match failed for %s, trying pattern search...", indicator.Value)
			iocs, err = h.repo.FindContaining(ctx, indicator.Value)
			if err != nil {
				log.Printf("⚠️  Failed pattern search for %s: %v", indicator.Value, err)
			}
		}

		if len(iocs) == 0 {
			// Not in Watchtower database
			enrichedIndicators = append(enrichedIndicators, EnrichedIndicator{
				Type:       indicator.Type,
				Value:      indicator.Value,
				InDatabase: false,
			})
			continue
		}

		// Enrich with Watchtower data
		sources := []string{}
		tags := []string{}
		threatTypes := []string{}
		for _, ioc := range iocs {
			sources = append(sources, ioc.Source)
			tags = append(tags, ioc.Tags...)
			threatTypes = append(threatTypes, ioc.ThreatType)
		}

		enrichedIndicators = append(enrichedIndicators, EnrichedIndicator{
			Type:        indicator.Type,
			Value:       indicator.Value,
			InDatabase:  true,
			Sources:     uniqueStrings(sources),
			Tags:        uniqueStrings(tags),
			ThreatTypes: uniqueStrings(threatTypes),
			FirstSeen:   iocs[0].FirstSeen,
		})
	}

	// Use LLM for intelligent triaging (if enabled)
	var triageResult *llm.TriageResult
	if h.llmTriager != nil && h.llmTriager.IsEnabled() {
		log.Printf("🤖 Running LLM triaging for alert %s...", payload.AlertID)

		// Build threat context
		threatContext := llm.ThreatContext{
			AlertID:        payload.AlertID,
			ThreatName:     payload.ThreatName,
			Classification: payload.Classification,
			Endpoint:       payload.Endpoint.ComputerName,
			OSType:         payload.Endpoint.OSType,
			IOCs:           make([]llm.IOCContext, len(enrichedIndicators)),
		}

		for i, ind := range enrichedIndicators {
			threatContext.IOCs[i] = llm.IOCContext{
				Type:        ind.Type,
				Value:       ind.Value,
				InDatabase:  ind.InDatabase,
				Sources:     ind.Sources,
				Tags:        ind.Tags,
				ThreatTypes: ind.ThreatTypes,
				FirstSeen:   ind.FirstSeen,
			}
		}

		// Run triaging
		result, err := h.llmTriager.Triage(ctx, threatContext)
		if err != nil {
			log.Printf("⚠️  LLM triaging failed: %v", err)
		} else {
			triageResult = result
			log.Printf("✅ LLM triaging complete - Severity: %s, Priority: %d, Confidence: %d%%",
				triageResult.Severity, triageResult.Priority, triageResult.Confidence)

			// Skip notification for likely false positives (configurable threshold)
			if triageResult.FalsePositive && triageResult.Confidence >= 80 {
				log.Printf("⏭️  Skipping notification - LLM identified as likely false positive")
				response := map[string]interface{}{
					"status":              "received",
					"alert_id":            payload.AlertID,
					"indicators_enriched": len(enrichedIndicators),
					"indicators_in_db":    countEnriched(enrichedIndicators),
					"slack_notification":  false,
					"llm_triaged":         true,
					"false_positive":      true,
				}
				writeJSON(w, http.StatusOK, response)
				return
			}
		}
	}

	// Send Slack notification if configured
	if h.slackNotifier != nil {
		// Convert to notifier types
		notifierAlert := notifier.SentinelOneAlert{
			AlertID:        payload.AlertID,
			ThreatName:     payload.ThreatName,
			Classification: payload.Classification,
			Endpoint: struct {
				ComputerName string
				OSType       string
			}{
				ComputerName: payload.Endpoint.ComputerName,
				OSType:       payload.Endpoint.OSType,
			},
		}

		notifierEnriched := make([]notifier.EnrichedIndicator, len(enrichedIndicators))
		for i, ind := range enrichedIndicators {
			notifierEnriched[i] = notifier.EnrichedIndicator{
				Type:        ind.Type,
				Value:       ind.Value,
				InDatabase:  ind.InDatabase,
				Sources:     ind.Sources,
				Tags:        ind.Tags,
				ThreatTypes: ind.ThreatTypes,
				FirstSeen:   ind.FirstSeen,
			}
		}

		// Send notification with or without LLM insights
		var err error
		if triageResult != nil {
			// Convert triageResult to notifier type
			notifierTriage := &notifier.TriageResult{
				Severity:      triageResult.Severity,
				Priority:      triageResult.Priority,
				Summary:       triageResult.Summary,
				Analysis:      triageResult.Analysis,
				Recommended:   triageResult.Recommended,
				FalsePositive: triageResult.FalsePositive,
				Confidence:    triageResult.Confidence,
			}
			err = h.slackNotifier.NotifySentinelOneDetectionWithTriage(notifierAlert, notifierEnriched, notifierTriage)
		} else {
			err = h.slackNotifier.NotifySentinelOneDetection(notifierAlert, notifierEnriched)
		}

		if err != nil {
			log.Printf("⚠️  Failed to send Slack notification: %v", err)
		} else {
			log.Printf("✅ Slack notification sent for alert %s", payload.AlertID)
		}
	}

	// Respond to SentinelOne
	response := map[string]interface{}{
		"status":              "received",
		"alert_id":            payload.AlertID,
		"indicators_enriched": len(enrichedIndicators),
		"indicators_in_db":    countEnriched(enrichedIndicators),
		"slack_notification":  h.slackNotifier != nil,
		"llm_triaged":         triageResult != nil,
	}
	writeJSON(w, http.StatusOK, response)
}

// Helper functions

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func countEnriched(indicators []EnrichedIndicator) int {
	count := 0
	for _, ind := range indicators {
		if ind.InDatabase {
			count++
		}
	}
	return count
}

// SentinelOne webhook payload structures

type SentinelOneAlert struct {
	AlertID        string              `json:"alertId"`
	ThreatName     string              `json:"threatName"`
	Classification string              `json:"classification"`
	Indicators     []SentinelOneIOC    `json:"indicators"`
	Endpoint       SentinelOneEndpoint `json:"endpoint"`
	Timestamp      string              `json:"timestamp"`
}

type SentinelOneIOC struct {
	Type  string `json:"type"` // SHA256, IPV4, IPV6, DNS, URL
	Value string `json:"value"`
}

type SentinelOneEndpoint struct {
	ComputerName string `json:"computerName"`
	OSType       string `json:"osType"`
	AgentVersion string `json:"agentVersion"`
}

type EnrichedIndicator struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	InDatabase  bool      `json:"in_database"`
	Sources     []string  `json:"sources,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	ThreatTypes []string  `json:"threat_types,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
}
