package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hive-corporation/watchtower/internal/core/domain"
	"github.com/hive-corporation/watchtower/internal/core/ports"
)

// STIXExporter exports IOCs in STIX 2.1 format for SIEM ingestion
type STIXExporter struct {
	repo ports.IOCRepository
}

func NewSTIXExporter(repo ports.IOCRepository) *STIXExporter {
	return &STIXExporter{repo: repo}
}

// Export generates STIX 2.1 formatted IOC feed
func (e *STIXExporter) Export(ctx context.Context, since time.Time) (string, error) {
	// Default to last 24 hours if no time specified
	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour)
	}

	// Fetch IOCs from database (limit to 10000 entries for performance)
	iocs, err := e.repo.FindSince(ctx, since, 10000)
	if err != nil {
		return "", fmt.Errorf("failed to fetch IOCs: %w", err)
	}

	bundle := STIXBundle{
		Type:        "bundle",
		ID:          fmt.Sprintf("bundle--%s", uuid.New().String()),
		SpecVersion: "2.1",
		Objects:     []STIXObject{},
	}

	// Convert domain IOCs to STIX indicators
	for _, ioc := range iocs {
		confidence := calculateConfidenceSTIX(ioc)
		indicator := e.convertToSTIX(ioc, confidence)
		bundle.Objects = append(bundle.Objects, indicator)
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal STIX bundle: %w", err)
	}

	return string(jsonData), nil
}

func (e *STIXExporter) convertToSTIX(ioc domain.IOC, confidence int) STIXObject {
	now := time.Now().UTC()

	// Build STIX pattern based on IOC type
	pattern := e.buildPattern(ioc)

	// Map IOC type to STIX indicator types
	indicatorTypes := e.mapIndicatorTypes(ioc.ThreatType)

	// External references
	externalRefs := []ExternalReference{
		{
			SourceName: ioc.Source,
			URL:        e.getSourceURL(ioc.Source),
		},
	}

	return STIXObject{
		Type:               "indicator",
		SpecVersion:        "2.1",
		ID:                 fmt.Sprintf("indicator--%s", uuid.New().String()),
		Created:            now.Format(time.RFC3339),
		Modified:           now.Format(time.RFC3339),
		Name:               fmt.Sprintf("%s Indicator", strings.ToUpper(string(ioc.Type))),
		Pattern:            pattern,
		PatternType:        "stix",
		ValidFrom:          ioc.FirstSeen.Format(time.RFC3339),
		IndicatorTypes:     indicatorTypes,
		Confidence:         confidence,
		Labels:             ioc.Tags,
		ExternalReferences: externalRefs,
	}
}

func (e *STIXExporter) buildPattern(ioc domain.IOC) string {
	// Build STIX 2.1 pattern based on IOC type
	switch ioc.Type {
	case domain.IPAddress:
		return fmt.Sprintf("[ipv4-addr:value = '%s']", ioc.Value)
	case domain.Domain:
		return fmt.Sprintf("[domain-name:value = '%s']", ioc.Value)
	case domain.URL:
		return fmt.Sprintf("[url:value = '%s']", ioc.Value)
	case domain.FileHash:
		// Detect hash type (SHA256, MD5, SHA1)
		hashType := detectHashType(ioc.Value)
		return fmt.Sprintf("[file:hashes.'%s' = '%s']", hashType, ioc.Value)
	case domain.Package:
		// Use software object for packages
		return fmt.Sprintf("[software:name = '%s']", ioc.Value)
	default:
		return fmt.Sprintf("[x-custom:value = '%s']", ioc.Value)
	}
}

func (e *STIXExporter) mapIndicatorTypes(threatType string) []string {
	// Map Watchtower threat types to STIX indicator types
	mapping := map[string][]string{
		"c2_server":             {"malicious-activity", "command-and-control"},
		"malware_distribution":  {"malicious-activity", "malware-download"},
		"phishing":              {"malicious-activity", "phishing"},
		"supply_chain_malware":  {"malicious-activity", "supply-chain-compromise"},
		"botnet":                {"malicious-activity", "botnet"},
		"generic_malware":       {"malicious-activity"},
		"anonymization_network": {"anomalous-activity"},
	}

	if types, ok := mapping[threatType]; ok {
		return types
	}
	return []string{"malicious-activity"}
}

func (e *STIXExporter) getSourceURL(source string) string {
	// Map sources to their URLs
	urls := map[string]string{
		"alienvault-otx":   "https://otx.alienvault.com",
		"urlhaus":          "https://urlhaus.abuse.ch",
		"digitalside":      "https://osint.digitalside.it",
		"tor-exit-nodes":   "https://check.torproject.org",
		"google-osv-npm":   "https://osv.dev",
		"google-osv-pypi":  "https://osv.dev",
		"google-osv-maven": "https://osv.dev",
		"google-osv-go":    "https://osv.dev",
	}

	if url, ok := urls[source]; ok {
		return url
	}
	return ""
}

func detectHashType(hash string) string {
	// Detect hash algorithm by length
	switch len(hash) {
	case 32:
		return "MD5"
	case 40:
		return "SHA-1"
	case 64:
		return "SHA-256"
	default:
		return "SHA-256" // default
	}
}

// STIX 2.1 data structures

type STIXBundle struct {
	Type        string       `json:"type"`
	ID          string       `json:"id"`
	SpecVersion string       `json:"spec_version"`
	Objects     []STIXObject `json:"objects"`
}

type STIXObject struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            string              `json:"created"`
	Modified           string              `json:"modified"`
	Name               string              `json:"name"`
	Pattern            string              `json:"pattern"`
	PatternType        string              `json:"pattern_type"`
	ValidFrom          string              `json:"valid_from"`
	IndicatorTypes     []string            `json:"indicator_types"`
	Confidence         int                 `json:"confidence"`
	Labels             []string            `json:"labels,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
}

type ExternalReference struct {
	SourceName string `json:"source_name"`
	URL        string `json:"url,omitempty"`
}

// calculateConfidenceSTIX generates a confidence score based on IOC attributes
func calculateConfidenceSTIX(ioc domain.IOC) int {
	confidence := 70 // Base confidence

	// Increase confidence for certain sources
	if ioc.Source == "alienvault-otx" || ioc.Source == "abusech-urlhaus" {
		confidence += 10
	}

	// Increase confidence for certain threat types
	if ioc.ThreatType == "malware_download" || ioc.ThreatType == "c2_server" {
		confidence += 5
	}

	// Increase confidence if multiple tags
	if len(ioc.Tags) > 3 {
		confidence += 5
	}

	// Cap at 100
	if confidence > 100 {
		confidence = 100
	}

	return confidence
}
