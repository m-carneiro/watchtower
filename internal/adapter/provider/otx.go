package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hive-corporation/watchtower/internal/core/domain"
)

const otxURL = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10&modified_since=7d"

type OTXProvider struct {
	client *http.Client
	apiKey string
}

func NewOTXProvider(client *http.Client, apiKey string) *OTXProvider {
	if client == nil {
		client = http.DefaultClient
	}
	return &OTXProvider{
		client: client,
		apiKey: apiKey,
	}
}

func (p *OTXProvider) Name() string {
	return "alienvault-otx"
}

type otxResponse struct {
	Results []otxPulse `json:"results"`
	Next    string     `json:"next"`
}

type otxPulse struct {
	Name string `json:"name"`

	AuthorName string `json:"author_name"`

	Created    string         `json:"created"`
	Indicators []otxIndicator `json:"indicators"`
	Tags       []string       `json:"tags"`
}

type otxIndicator struct {
	Indicator string `json:"indicator"`
	Type      string `json:"type"` // ex: IPv4, domain, FileHash-SHA256
	Created   string `json:"created"`
}

func (p *OTXProvider) FetchIOCS(ctx context.Context) ([]domain.IOC, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("OTX API Key is missing")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", otxURL, nil)
	if err != nil {
		return nil, err
	}

	// OTX exige a Key no Header
	req.Header.Set("X-OTX-API-KEY", p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OTX API error: status %d", resp.StatusCode)
	}

	var data otxResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode OTX json: %w", err)
	}

	var iocs []domain.IOC

	// Itera sobre os Pulsos
	for _, pulse := range data.Results {
		// Itera sobre os Indicadores dentro do Pulso
		for _, ind := range pulse.Indicators {

			// Converte o Tipo do OTX para o Nosso Tipo
			myType := mapOTXType(ind.Type)
			if myType == "" {
				continue // Ignora tipos que não sabemos lidar (ex: email, cve)
			}

			// Parsing de datas (OTX usa ISO8601 variada, simplificando aqui)
			firstSeen, _ := time.Parse(time.RFC3339, ind.Created)
			if firstSeen.IsZero() {
				firstSeen = time.Now()
			}

			iocs = append(iocs, domain.IOC{
				Value:        ind.Indicator,
				Type:         myType,
				Source:       p.Name(),
				ThreatType:   pulse.Name, // Usamos o nome do Pulso como "Ameaça"
				Tags:         pulse.Tags,
				FirstSeen:    firstSeen,
				DateIngested: time.Now(),
			})
		}
	}

	return iocs, nil
}

func mapOTXType(otxType string) domain.IOCType {
	switch otxType {
	case "IPv4", "IPv6":
		return domain.IPAddress
	case "domain", "hostname":
		return domain.Domain
	case "url":
		return domain.URL
	case "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256":
		return domain.FileHash
	default:
		return ""
	}
}
