package llm

import (
	"log"
	"strings"
)

// Guardrails provides rule-based validation and confidence adjustments
// to reduce false positives and improve LLM accuracy

// KnownGoodIndicators are indicators that should never be marked as malicious
var KnownGoodIndicators = []string{
	// Microsoft domains
	"microsoft.com",
	"windowsupdate.com",
	"update.microsoft.com",
	"msftconnecttest.com",
	"office.com",
	"live.com",

	// Cloud providers
	"amazonaws.com",
	"cloudfront.net",
	"googleapis.com",
	"gstatic.com",
	"azure.com",

	// CDNs
	"cloudflare.com",
	"akamai.net",
	"fastly.net",

	// Common services
	"apple.com",
	"google.com",
	"mozilla.org",
	"ubuntu.com",
	"debian.org",
}

// HighRiskThreatTypes indicate confirmed malicious activity
var HighRiskThreatTypes = []string{
	"c2_server",
	"c2",
	"command_and_control",
	"malware_download",
	"ransomware",
	"botnet",
	"phishing",
	"cryptominer",
	"backdoor",
	"trojan",
	"rat",
	"webshell",
}

// GuardrailConfig controls guardrail behavior
type GuardrailConfig struct {
	MinConfidenceForFalsePositive int    // Minimum confidence to mark as FP (default: 85)
	RequireThreatIntelForCritical bool   // Require threat intel match for critical severity (default: true)
	MaxSeverityWithoutThreatIntel string // Max severity without threat intel (default: "medium")
}

// DefaultGuardrailConfig returns the default configuration
func DefaultGuardrailConfig() GuardrailConfig {
	return GuardrailConfig{
		MinConfidenceForFalsePositive: 85,
		RequireThreatIntelForCritical: true,
		MaxSeverityWithoutThreatIntel: "medium",
	}
}

// ApplyPreLLMGuardrails checks if we can make a determination before calling LLM
// Returns (result, shouldSkipLLM)
func ApplyPreLLMGuardrails(threat ThreatContext, config GuardrailConfig) (*TriageResult, bool) {
	// Check if all IOCs are known good
	allKnownGood := true
	hasIOCs := len(threat.IOCs) > 0

	for _, ioc := range threat.IOCs {
		if !isKnownGoodIndicator(ioc.Value) {
			allKnownGood = false
			break
		}
	}

	if hasIOCs && allKnownGood {
		log.Printf("⚡ Pre-filter: All IOCs are known good - marking as false positive")
		RecordGuardrail("pre", "skip")
		return &TriageResult{
			Severity:      "info",
			Priority:      5,
			Summary:       "All indicators are legitimate infrastructure",
			Analysis:      "Analysis shows all indicators belong to known legitimate services (Microsoft, Google, cloud providers, etc.). This is a false positive.",
			Recommended:   []string{"Mark as false positive", "Adjust detection rules to exclude legitimate services"},
			FalsePositive: true,
			Confidence:    95,
		}, true
	}

	// Check if any IOC has high-risk threat types
	hasHighRiskIOC := false
	highRiskTypes := []string{}

	for _, ioc := range threat.IOCs {
		if ioc.InDatabase {
			for _, threatType := range ioc.ThreatTypes {
				if isHighRiskThreatType(threatType) {
					hasHighRiskIOC = true
					highRiskTypes = append(highRiskTypes, threatType)
				}
			}
		}
	}

	if hasHighRiskIOC {
		log.Printf("⚡ Pre-filter: High-risk threat types detected: %v", highRiskTypes)
		RecordGuardrail("pre", "skip")
		return &TriageResult{
			Severity:      "high",
			Priority:      2,
			Summary:       "Confirmed malicious activity detected in threat intelligence",
			Analysis:      "Multiple threat intelligence sources confirm this as malicious activity: " + strings.Join(highRiskTypes, ", "),
			Recommended:   []string{"Isolate affected endpoint immediately", "Conduct forensic analysis", "Check for lateral movement", "Scan other endpoints for similar IOCs"},
			FalsePositive: false,
			Confidence:    90,
		}, true
	}

	// No pre-filter match - proceed with LLM
	return nil, false
}

// ApplyPostLLMGuardrails validates and adjusts LLM output
func ApplyPostLLMGuardrails(result *TriageResult, threat ThreatContext, config GuardrailConfig) *TriageResult {
	log.Printf("🛡️  Applying post-LLM guardrails...")

	// Validate and normalize fields
	result.Severity = normalizeSeverity(result.Severity)
	result.Priority = normalizePriority(result.Priority, result.Severity)
	result.Confidence = normalizeConfidence(result.Confidence)

	// Count IOCs in threat database
	iocsInDB := 0
	hasHighRiskTypes := false

	for _, ioc := range threat.IOCs {
		if ioc.InDatabase {
			iocsInDB++
			for _, threatType := range ioc.ThreatTypes {
				if isHighRiskThreatType(threatType) {
					hasHighRiskTypes = true
				}
			}
		}
	}

	// Guardrail 1: Cannot mark as false positive if IOCs are in threat database
	if result.FalsePositive && iocsInDB > 0 {
		log.Printf("⚠️  Guardrail: LLM marked as false positive but %d IOCs found in threat DB - overriding", iocsInDB)
		RecordGuardrail("post", "override")
		result.FalsePositive = false
		result.Confidence = max(result.Confidence-20, 50) // Reduce confidence due to inconsistency

		// Adjust to at least medium severity
		if result.Severity == "info" || result.Severity == "low" {
			result.Severity = "medium"
			result.Priority = 3
		}
	}

	// Guardrail 2: High-risk threat types cannot be low severity
	if hasHighRiskTypes && (result.Severity == "info" || result.Severity == "low") {
		log.Printf("⚠️  Guardrail: High-risk threat types detected but severity is %s - upgrading to high", result.Severity)
		RecordGuardrail("post", "override")
		result.Severity = "high"
		result.Priority = 2
		result.FalsePositive = false
		result.Confidence = max(result.Confidence+10, 85) // Boost confidence
	}

	// Guardrail 3: Cannot be critical/high severity without threat intel (unless high confidence)
	if config.RequireThreatIntelForCritical && iocsInDB == 0 {
		if result.Severity == "critical" {
			log.Printf("⚠️  Guardrail: Critical severity without threat intel - downgrading to high")
			RecordGuardrail("post", "downgrade")
			result.Severity = "high"
			result.Priority = 2
			result.Confidence = min(result.Confidence, 75)
		} else if result.Severity == "high" && result.Confidence < 80 {
			log.Printf("⚠️  Guardrail: High severity without threat intel and low confidence - downgrading to medium")
			RecordGuardrail("post", "downgrade")
			result.Severity = "medium"
			result.Priority = 3
			result.Confidence = min(result.Confidence, 70)
		}
	}

	// Guardrail 4: Boost confidence if multiple threat intel sources agree
	if iocsInDB > 0 {
		uniqueSources := make(map[string]bool)
		for _, ioc := range threat.IOCs {
			for _, source := range ioc.Sources {
				uniqueSources[source] = true
			}
		}

		if len(uniqueSources) >= 3 {
			log.Printf("✅ Guardrail: Multiple threat intel sources (%d) - boosting confidence", len(uniqueSources))
			RecordGuardrail("post", "boost")
			result.Confidence = min(result.Confidence+15, 98)
		}
	}

	// Guardrail 5: False positive requires high confidence
	if result.FalsePositive && result.Confidence < config.MinConfidenceForFalsePositive {
		log.Printf("⚠️  Guardrail: False positive has low confidence (%d%% < %d%%) - marking as uncertain",
			result.Confidence, config.MinConfidenceForFalsePositive)
		result.FalsePositive = false
		result.Severity = "low"
		result.Priority = 4
		result.Analysis = result.Analysis + " (Note: Marked for analyst review due to uncertainty)"
	}

	// Guardrail 6: Validate severity/priority alignment
	result.Priority = ensurePriorityMatchesSeverity(result.Priority, result.Severity)

	// Guardrail 7: Ensure recommended actions exist for non-false-positives
	if !result.FalsePositive && len(result.Recommended) == 0 {
		result.Recommended = getDefaultRecommendations(result.Severity)
	}

	log.Printf("✅ Guardrails applied: severity=%s, confidence=%d%%, false_positive=%v",
		result.Severity, result.Confidence, result.FalsePositive)

	return result
}

// Helper functions

func isKnownGoodIndicator(value string) bool {
	valueLower := strings.ToLower(value)
	for _, good := range KnownGoodIndicators {
		if strings.Contains(valueLower, good) {
			return true
		}
	}
	return false
}

func isHighRiskThreatType(threatType string) bool {
	threatTypeLower := strings.ToLower(threatType)
	for _, risk := range HighRiskThreatTypes {
		if strings.Contains(threatTypeLower, risk) {
			return true
		}
	}
	return false
}

func normalizeSeverity(severity string) string {
	severity = strings.ToLower(strings.TrimSpace(severity))
	validSeverities := []string{"critical", "high", "medium", "low", "info"}
	for _, valid := range validSeverities {
		if severity == valid {
			return severity
		}
	}
	return "medium" // Default to medium if invalid
}

func normalizePriority(priority int, severity string) int {
	if priority < 1 {
		priority = 1
	}
	if priority > 5 {
		priority = 5
	}
	return priority
}

func normalizeConfidence(confidence int) int {
	if confidence < 0 {
		return 0
	}
	if confidence > 100 {
		return 100
	}
	return confidence
}

func ensurePriorityMatchesSeverity(priority int, severity string) int {
	// Ensure priority aligns with severity
	severityToPriority := map[string]int{
		"critical": 1,
		"high":     2,
		"medium":   3,
		"low":      4,
		"info":     5,
	}

	expectedPriority := severityToPriority[severity]
	if expectedPriority == 0 {
		return priority
	}

	// Allow ±1 deviation but enforce general alignment
	if abs(priority-expectedPriority) > 1 {
		log.Printf("⚠️  Adjusting priority from %d to %d to match severity %s", priority, expectedPriority, severity)
		return expectedPriority
	}

	return priority
}

func getDefaultRecommendations(severity string) []string {
	switch severity {
	case "critical":
		return []string{
			"Immediately isolate the affected endpoint",
			"Initiate incident response procedures",
			"Conduct forensic analysis",
			"Check for indicators of lateral movement",
		}
	case "high":
		return []string{
			"Isolate the endpoint from the network",
			"Review endpoint activity logs",
			"Scan for additional compromised systems",
			"Collect forensic evidence",
		}
	case "medium":
		return []string{
			"Investigate endpoint activity",
			"Monitor for suspicious behavior",
			"Review logs for related indicators",
		}
	case "low":
		return []string{
			"Monitor the endpoint",
			"Document findings for future reference",
		}
	default:
		return []string{
			"Review and document for analysis",
		}
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
