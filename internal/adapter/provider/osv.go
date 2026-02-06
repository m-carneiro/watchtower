package provider

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hive-corporation/watchtower/internal/core/domain"
)

// Base URL para o dump de malwares conhecidos do OSV
const osvBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

type OSVProvider struct {
	client    *http.Client
	ecosystem string
}

func NewOSVProvider(client *http.Client, ecosystem string) *OSVProvider {
	if client == nil {
		client = http.DefaultClient
	}
	return &OSVProvider{
		client:    client,
		ecosystem: ecosystem,
	}
}

func (p *OSVProvider) Name() string {
	return fmt.Sprintf("google-osv-%s", strings.ToLower(p.ecosystem))
}

// Estrutura do JSON do OSV com versões
type osvEntry struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Versions []string `json:"versions"` // Lista explícita de versões afetadas
		Ranges   []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced,omitempty"`
				Fixed        string `json:"fixed,omitempty"`
				LastAffected string `json:"last_affected,omitempty"`
			} `json:"events"`
		} `json:"ranges,omitempty"` // Ranges de versões (para contexto futuro)
	} `json:"affected"`
	Modified time.Time `json:"modified"`
}

func (p *OSVProvider) FetchIOCS(ctx context.Context) ([]domain.IOC, error) {
	// 1. Construir URL baseada no ecossistema
	url := fmt.Sprintf("%s/%s/all.zip", osvBaseURL, p.ecosystem)

	// 2. Baixar o ZIP
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Ler tudo para memória (o zip não é gigante, ~alguns MBs)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(bodyBytes), int64(len(bodyBytes)))
	if err != nil {
		return nil, err
	}

	var iocs []domain.IOC

	// 2. Ler cada JSON dentro do ZIP
	for _, file := range zipReader.File {
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			continue
		}

		var entry osvEntry
		if err := json.NewDecoder(rc).Decode(&entry); err == nil {
			// Extrair nomes de pacotes e versões afetadas
			for _, affected := range entry.Affected {
				pkgName := affected.Package.Name
				if pkgName == "" {
					continue
				}

				// Se há versões explícitas, criar um IOC por versão
				if len(affected.Versions) > 0 {
					for _, version := range affected.Versions {
						if version == "" {
							continue
						}
						iocs = append(iocs, domain.IOC{
							Value:        pkgName,
							Type:         domain.Package,
							Source:       p.Name(),
							ThreatType:   "supply_chain_malware",
							Tags:         []string{entry.ID, "osv"},
							Version:      version,
							FirstSeen:    entry.Modified,
							DateIngested: time.Now(),
						})
					}
				} else {
					// Sem versões explícitas: criar IOC sem versão (todo o pacote é considerado vulnerável)
					iocs = append(iocs, domain.IOC{
						Value:        pkgName,
						Type:         domain.Package,
						Source:       p.Name(),
						ThreatType:   "supply_chain_malware",
						Tags:         []string{entry.ID, "osv"},
						Version:      "", // Sem versão específica
						FirstSeen:    entry.Modified,
						DateIngested: time.Now(),
					})
				}
			}
		}
		if err := rc.Close(); err != nil {
			log.Printf("Warning: failed to close zip entry: %v", err)
		}
	}

	return iocs, nil
}
