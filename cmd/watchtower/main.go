package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/hive-corporation/watchtower/internal/adapter/grpcmw"
	"github.com/hive-corporation/watchtower/internal/adapter/handler"
	"github.com/hive-corporation/watchtower/internal/adapter/repository"
	"github.com/hive-corporation/watchtower/internal/config"
	pb "github.com/hive-corporation/watchtower/proto"
)

func main() {
	dbURL := config.GetEnv("DATABASE_URL", "postgres://admin:secretpassword@localhost:5432/watchtower")
	dbPool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer dbPool.Close()

	repo := repository.NewPostgresRepository(dbPool)
	grpcHandler := handler.NewGrpcServer(repo)

	// Get listen address from environment (default: localhost for security)
	listenAddr := os.Getenv("GRPC_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "localhost:50051" // Secure default - localhost only
	}

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	var opts []grpc.ServerOption

	// App-level token authentication (defense in depth, independent of mTLS).
	if authToken := os.Getenv("GRPC_AUTH_TOKEN"); authToken != "" {
		opts = append(opts, grpc.UnaryInterceptor(grpcmw.UnaryTokenAuthInterceptor(authToken)))
		log.Println("✅ gRPC token authentication enabled")
	} else {
		log.Println("⚠️  GRPC_AUTH_TOKEN not set - gRPC token auth disabled (dev only)")
	}

	// Transport security: TLS, upgraded to mutual TLS when a client CA is set.
	certFile := os.Getenv("GRPC_TLS_CERT")
	keyFile := os.Getenv("GRPC_TLS_KEY")
	if certFile != "" && keyFile != "" {
		clientCA := os.Getenv("GRPC_TLS_CLIENT_CA")
		creds, err := grpcmw.ServerTLS(certFile, keyFile, clientCA)
		if err != nil {
			log.Fatalf("failed to configure gRPC TLS: %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
		if clientCA != "" {
			log.Println("✅ gRPC mTLS enabled (client certificate required)")
		} else {
			log.Println("✅ gRPC TLS enabled")
		}
	} else {
		log.Println("⚠️  GRPC_TLS_CERT/GRPC_TLS_KEY not set - gRPC serving plaintext (dev only)")
	}

	s := grpc.NewServer(opts...)

	pb.RegisterWatchtowerServer(s, grpcHandler)

	// Reflection exposes the full service schema; keep it off unless explicitly
	// enabled for local development.
	if config.GetEnv("GRPC_ENABLE_REFLECTION", "false") == "true" {
		reflection.Register(s)
		log.Println("⚠️  gRPC reflection enabled")
	}

	go func() {
		log.Printf("🚀 Watchtower gRPC API listening on %s\n", listenAddr)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	s.GracefulStop()
}
