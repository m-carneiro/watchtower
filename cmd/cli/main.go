package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/hive-corporation/watchtower/proto"
)

func main() {
	targetFile := flag.String("file", "go.mod", "Caminho para o go.mod")
	serverAddr := flag.String("server", "localhost:50051", "Endereço da API Watchtower")
	useTLS := flag.Bool("tls", false, "Connect using TLS")
	caFile := flag.String("ca", "", "CA certificate to verify the server (optional, implies -tls)")
	certFile := flag.String("cert", "", "Client certificate for mTLS (implies -tls)")
	keyFile := flag.String("key", "", "Client private key for mTLS (implies -tls)")
	token := flag.String("token", "", "Bearer token for gRPC authentication")
	flag.Parse()

	transportCreds, err := clientCredentials(*useTLS, *caFile, *certFile, *keyFile)
	if err != nil {
		log.Fatalf("❌ failed to configure transport credentials: %v", err)
	}

	conn, err := grpc.NewClient(*serverAddr, grpc.WithTransportCredentials(transportCreds))
	if err != nil {
		log.Fatalf("❌ error connecting to Watchtower: %v", err)
	}
	defer conn.Close()

	client := pb.NewWatchtowerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Attach the bearer token (if any) to every outgoing request.
	if *token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+*token)
	}

	file, err := os.Open(*targetFile)
	if err != nil {
		log.Fatalf("❌ error reading file: %v", err)
	}
	defer file.Close()

	fmt.Printf("🔍 analyzing %s against Intelligence Database at %s...\n\n", *targetFile, *serverAddr)

	scanner := bufio.NewScanner(file)
	threatsFound := 0
	scanned := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		pkgName := parts[0]
		if pkgName == "require" || pkgName == "module" || pkgName == "go" || pkgName == "//" {
			if len(parts) > 2 && parts[0] == "require" {
				pkgName = parts[1]
			} else {
				continue
			}
		}

		pkgName = strings.TrimSuffix(pkgName, "/v2")

		scanned++
		resp, err := client.CheckIOC(ctx, &pb.CheckRequest{Value: pkgName})
		if err != nil {
			log.Printf("⚠️ error checking %s: %v", pkgName, err)
			continue
		}

		if resp.Exists && resp.ActionBlock {
			fmt.Printf("🚨 [BLOCKED] %s -> %s (Score: %d)\n", pkgName, resp.ThreatType, resp.ConfidenceScore)
			threatsFound++
		} else {
			fmt.Printf("✅ [CLEAN] %s\n", pkgName)
		}
	}

	fmt.Println("------------------------------------------------")
	if threatsFound > 0 {
		fmt.Printf("❌ FAIL: %d malicious dependencies found.\n", threatsFound)
		os.Exit(1)
	}

	fmt.Printf("✅ SUCCESS: %d dependencies checked. No threats found.\n", scanned)
	os.Exit(0)
}

// clientCredentials builds the gRPC transport credentials for the CLI. It stays
// plaintext (insecure) by default for local development, and switches to TLS or
// mTLS when -tls / -ca / -cert / -key are provided.
func clientCredentials(useTLS bool, caFile, certFile, keyFile string) (credentials.TransportCredentials, error) {
	if !useTLS && caFile == "" && certFile == "" && keyFile == "" {
		return insecure.NewCredentials(), nil
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certificates in CA %q", caFile)
		}
		cfg.RootCAs = pool
	}

	if certFile != "" || keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(cfg), nil
}
