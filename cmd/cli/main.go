package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/hive-corporation/watchtower/proto"
)

func main() {
	targetFile := flag.String("file", "go.mod", "Caminho para o go.mod")
	serverAddr := flag.String("server", "localhost:50051", "Endereço da API Watchtower")
	flag.Parse()

	conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("❌ error connecting to Watchtower: %v", err)
	}
	defer conn.Close()

	client := pb.NewWatchtowerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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
