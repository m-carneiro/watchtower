package provider

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hive-corporation/watchtower/internal/core/domain"
)

const urlHausCSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"

type URLHausProvider struct {
	client *http.Client
}

func NewURLHausProvider(client *http.Client) *URLHausProvider {
	if client == nil {
		client = http.DefaultClient
	}
	return &URLHausProvider{
		client: client,
	}
}

func (p *URLHausProvider) Name() string {
	return "abusech-urlhaus"
}

func (p *URLHausProvider) FetchIOCS(ctx context.Context) ([]domain.IOC, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlHausCSV, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch urlhaus: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	reader := csv.NewReader(resp.Body)
	reader.Comment = '#'
	reader.FieldsPerRecord = -1

	var iocs []domain.IOC

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading csv line: %w", err)
		}
		// 0: id, 1: dateadded, 2: url, 3: url_status, 4: last_online,
		// 5: threat, 6: tags, 7: urlhaus_link, 8: reporter
		// if record[3] != "online" { continue }

		firstSeen, _ := time.Parse("2006-01-02 15:04:05", record[1])

		tags := strings.Split(record[6], ",")

		baseIOC := domain.IOC{
			Value:        record[2],
			Type:         domain.URL,
			Source:       p.Name(),
			ThreatType:   record[5],
			Tags:         tags,
			FirstSeen:    firstSeen,
			DateIngested: time.Now(),
		}

		// Extract components (URL + IP/domain) for better matching
		components := domain.ExtractIOCComponents(record[2], baseIOC)
		iocs = append(iocs, components...)
	}

	return iocs, nil
}
