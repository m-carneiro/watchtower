package provider

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hive-corporation/watchtower/internal/core/domain"
)

// URLListProvider fetches lists of URLs and automatically extracts IP/domain components
// This solves the problem where searching for "198.0.2.12" wouldn't match "http://198.0.2.12/malware.sh"
type URLListProvider struct {
	client       *http.Client
	url          string
	providerName string
	threatType   string
}

func NewURLListProvider(client *http.Client, providerName string, feedURL string, threatType string) *URLListProvider {
	return &URLListProvider{
		client:       client,
		providerName: providerName,
		url:          feedURL,
		threatType:   threatType,
	}
}

func (p *URLListProvider) Name() string {
	return p.providerName
}

func (p *URLListProvider) FetchIOCS(ctx context.Context) ([]domain.IOC, error) {
	fmt.Printf("📥 Fetching %s from %s (with component extraction)\n", p.providerName, p.url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch IOCs from %s: %s", p.url, resp.Status)
	}

	var iocs []domain.IOC
	scanner := bufio.NewScanner(resp.Body)
	lineCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineCount++

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Remove inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "" {
			continue
		}

		now := time.Now()

		// Detect if it's a URL or plain IP/domain
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			// It's a URL - extract components
			baseIOC := domain.IOC{
				Value:        line,
				Type:         domain.URL,
				Source:       p.providerName,
				ThreatType:   p.threatType,
				Tags:         []string{"malware-url", "threat-feed"},
				Version:      "",
				FirstSeen:    now,
				DateIngested: now,
			}

			// Extract all components (URL + IP/domain)
			components := domain.ExtractIOCComponents(line, baseIOC)
			iocs = append(iocs, components...)

		} else if parsedURL, err := url.Parse("http://" + line); err == nil && parsedURL.Host != "" {
			// Might be a domain or IP without protocol
			// Try adding http:// prefix
			fullURL := "http://" + line

			baseIOC := domain.IOC{
				Value:        fullURL,
				Type:         domain.URL,
				Source:       p.providerName,
				ThreatType:   p.threatType,
				Tags:         []string{"malware-url", "threat-feed"},
				Version:      "",
				FirstSeen:    now,
				DateIngested: now,
			}

			components := domain.ExtractIOCComponents(fullURL, baseIOC)
			iocs = append(iocs, components...)

		} else {
			// Plain value (could be IP, domain, or hash)
			iocType := detectIOCType(line)
			iocs = append(iocs, domain.IOC{
				Value:        line,
				Type:         iocType,
				Source:       p.providerName,
				ThreatType:   p.threatType,
				Tags:         []string{"threat-feed"},
				Version:      "",
				FirstSeen:    now,
				DateIngested: now,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	fmt.Printf("✅ %s: Parsed %d lines, extracted %d IOCs (including components)\n",
		p.providerName, lineCount, len(iocs))

	return iocs, nil
}

// detectIOCType attempts to determine IOC type from the value
func detectIOCType(value string) domain.IOCType {
	// Try to parse as URL first
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return domain.URL
	}

	// Check for IP pattern (simple check)
	parts := strings.Split(value, ".")
	if len(parts) == 4 {
		// Might be an IP
		allNumbers := true
		for _, part := range parts {
			if len(part) == 0 || len(part) > 3 {
				allNumbers = false
				break
			}
			for _, c := range part {
				if c < '0' || c > '9' {
					allNumbers = false
					break
				}
			}
		}
		if allNumbers {
			return domain.IPAddress
		}
	}

	// Check for hash (32, 40, or 64 chars hex)
	if len(value) == 32 || len(value) == 40 || len(value) == 64 {
		isHex := true
		for _, c := range value {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				isHex = false
				break
			}
		}
		if isHex {
			return domain.FileHash
		}
	}

	// Default to domain
	return domain.Domain
}
