package exporter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hive-corporation/watchtower/internal/core/domain"
	"github.com/hive-corporation/watchtower/internal/core/ports"
)

// CEFExporter exports IOCs in Common Event Format for SIEM ingestion
type CEFExporter struct {
	repo ports.IOCRepository
}

func NewCEFExporter(repo ports.IOCRepository) *CEFExporter {
	return &CEFExporter{repo: repo}
}

// Export generates CEF-formatted IOC feed
// Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
func (e *CEFExporter) Export(ctx context.Context, since time.Time) (string, error) {
	// Default to last 24 hours if no time specified
	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour)
	}

	// Fetch IOCs from database (limit to 10000 entries for performance)
	iocs, err := e.repo.FindSince(ctx, since, 10000)
	if err != nil {
		return "", fmt.Errorf("failed to fetch IOCs: %w", err)
	}

	var output strings.Builder

	// Convert domain IOCs to CEF entries
	for _, ioc := range iocs {
		cefEntry := CEFEntry{
			Value:      ioc.Value,
			Type:       ioc.Type,
			ThreatType: ioc.ThreatType,
			Sources:    []string{ioc.Source},
			Tags:       ioc.Tags,
			Confidence: calculateConfidence(ioc),
			FirstSeen:  ioc.FirstSeen,
		}

		cefLine := e.formatCEF(cefEntry)
		output.WriteString(cefLine)
		output.WriteString("\n")
	}

	return output.String(), nil
}

func (e *CEFExporter) formatCEF(ioc CEFEntry) string {
	// CEF Header
	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

	vendor := "Watchtower"
	product := "ThreatIntel"
	version := "1.0"
	signatureID := string(ioc.Type)
	name := fmt.Sprintf("%s IOC Detected", strings.ToUpper(string(ioc.Type)))
	severity := calculateSeverity(ioc.Confidence)

	// CEF Extensions (key=value pairs)
	extensions := []string{
		fmt.Sprintf("src=%s", escapeField(ioc.Value)),
		"cn1Label=ConfidenceScore",
		fmt.Sprintf("cn1=%d", ioc.Confidence),
		"cs1Label=ThreatType",
		fmt.Sprintf("cs1=%s", escapeField(ioc.ThreatType)),
		"cs2Label=Sources",
		fmt.Sprintf("cs2=%s", escapeField(strings.Join(ioc.Sources, ","))),
		"cs3Label=Tags",
		fmt.Sprintf("cs3=%s", escapeField(strings.Join(ioc.Tags, ","))),
		fmt.Sprintf("rt=%d", ioc.FirstSeen.Unix()*1000), // milliseconds
	}

	extensionStr := strings.Join(extensions, " ")

	// Build CEF line
	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		vendor, product, version, signatureID, name, severity, extensionStr)
}

func calculateSeverity(confidence int) int {
	// Map confidence (0-100) to CEF severity (0-10)
	if confidence >= 90 {
		return 10 // Critical
	} else if confidence >= 80 {
		return 8 // High
	} else if confidence >= 70 {
		return 6 // Medium
	} else if confidence >= 60 {
		return 4 // Low
	}
	return 2 // Info
}

func escapeField(s string) string {
	// Escape special characters in CEF fields
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

// CEFEntry represents an IOC for CEF export
type CEFEntry struct {
	Value      string
	Type       domain.IOCType
	ThreatType string
	Sources    []string
	Tags       []string
	Confidence int
	FirstSeen  time.Time
}

// calculateConfidence generates a confidence score based on IOC attributes
func calculateConfidence(ioc domain.IOC) int {
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
