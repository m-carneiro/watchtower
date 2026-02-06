package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	"github.com/hive-corporation/watchtower/internal/adapter/provider"
	"github.com/hive-corporation/watchtower/internal/adapter/repository"
	"github.com/hive-corporation/watchtower/internal/core/domain"
	"github.com/hive-corporation/watchtower/internal/core/ports"
)

func main() {
	// Load .env file if it exists (optional - not all providers need API keys)
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  No .env file found (this is fine if you don't need API keys)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	log.Println("🔌 Database connection...")
	dbURL := "postgres://admin:secretpassword@localhost:5432/watchtower"
	dbPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("❌ Error connecting to database: %v", err)
	}
	defer dbPool.Close()

	repo := repository.NewPostgresRepository(dbPool)

	otxKey := os.Getenv("OTX_API_KEY")
	if otxKey == "" {
		log.Println("⚠️ OTX_API_KEY not found. AlienVault feed will be ignored.")
	}
	client := http.DefaultClient

	feeds := []ports.ThreatProvider{
		provider.NewURLHausProvider(client),
		provider.NewSimpleListProvider(client,
			"abusech-feodo",
			"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
			"botnet_c2",
		),

		provider.NewSimpleListProvider(client,
			"cins-army",
			"https://cinsscore.com/list/ci-badguys.txt",
			"bad_reputation",
		),

		provider.NewSimpleListProvider(client,
			"binary-defense",
			"https://binarydefense.com/banlist.txt",
			"network_attack",
		),

		provider.NewSimpleListProvider(client,
			"digitalside",
			"https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt",
			"generic_malware",
		),

		provider.NewSimpleListProvider(client,
			"tor-exit-nodes",
			"https://check.torproject.org/torbulkexitlist",
			"anonymization_network",
		),

		// Supply chain malware detection - OSV Database (multi-ecosystem)
		provider.NewOSVProvider(client, "Go"),
		provider.NewOSVProvider(client, "npm"),
		provider.NewOSVProvider(client, "PyPI"),
		provider.NewOSVProvider(client, "Maven"),
	}

	if otxKey != "" {
		feeds = append(feeds, provider.NewOTXProvider(client, otxKey))
	}

	iocChannel := make(chan domain.IOC, 2000) // Buffer para não travar o download
	var wg sync.WaitGroup

	log.Println("🚀 Threat intel ingestion started...")
	for _, feed := range feeds {
		wg.Add(1)
		go func(f ports.ThreatProvider) {
			defer wg.Done()
			log.Printf("📥 Downloading feed: %s...", f.Name())

			iocs, err := f.FetchIOCS(ctx)
			if err != nil {
				log.Printf("❌ Failed to download feed %s: %v", f.Name(), err)
				return
			}

			log.Printf("✅ %s returned %d IOCs. Sending to processing...", f.Name(), len(iocs))

			for _, ioc := range iocs {
				select {
				case iocChannel <- ioc:
				case <-ctx.Done():
					return // Aborta se estourar o tempo
				}
			}
		}(feed)
	}

	go func() {
		wg.Wait()
		close(iocChannel)
		log.Println("🔒 All downloads finished. Channel closed.")
	}()

	var batch []domain.IOC
	batchSize := 2000
	totalSaved := 0

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("💾 Starting persistence in Postgres...")

LoopPrincipal:
	for {
		select {
		case ioc, ok := <-iocChannel:
			if !ok {
				// Canal fechou e não tem mais dados
				break LoopPrincipal
			}

			batch = append(batch, ioc)

			if len(batch) >= batchSize {
				if err := repo.SaveBatch(ctx, batch); err != nil {
					log.Printf("❌ Error saving batch: %v", err)
				} else {
					totalSaved += len(batch)
					log.Printf("📦 Batch saved: %d items (Total: %d)", len(batch), totalSaved)
				}
				batch = nil
			}

		case <-ticker.C:
			if len(batch) > 0 {
				if err := repo.SaveBatch(ctx, batch); err != nil {
					log.Printf("❌ Error saving batch (ticker): %v", err)
				} else {
					totalSaved += len(batch)
					log.Printf("⏰ Batch saved by time: %d items (Total: %d)", len(batch), totalSaved)
				}
				batch = nil
			}
		}
	}

	if len(batch) > 0 {
		if err := repo.SaveBatch(ctx, batch); err != nil {
			log.Printf("❌ Error saving batch final: %v", err)
		} else {
			totalSaved += len(batch)
		}
	}

	log.Printf("🏁 Threat intel ingestion finished! Total of IOCs in database: %d", totalSaved)
}
