package provider

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hive-corporation/watchtower/internal/core/domain"
)

type SimpleListProvider struct {
	client       *http.Client
	url          string
	providerName string
	threatType   string
}

func NewSimpleListProvider(client *http.Client, providerName string, url string, threatType string) *SimpleListProvider {
	return &SimpleListProvider{
		client:       client,
		providerName: providerName,
		url:          url,
		threatType:   threatType,
	}
}

func (p *SimpleListProvider) Name() string {
	return p.providerName
}

func (p *SimpleListProvider) FetchIOCS(ctx context.Context) ([]domain.IOC, error) {
	fmt.Printf("DEBUG: Fetching %s from %s\n", p.providerName, p.url)

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
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		if idx := strings.Index(line, ":"); idx != -1 {
			line = line[:idx]
		}

		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}

		if !strings.Contains(line, ".") {
			continue
		}

		iocs = append(iocs, domain.IOC{
			Value:        line,
			Type:         domain.IPAddress,
			Source:       p.providerName,
			ThreatType:   p.threatType,
			Tags:         []string{"blocklist", "network_attack"},
			FirstSeen:    time.Now(),
			DateIngested: time.Now(),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return iocs, nil
}
