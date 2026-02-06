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

	"github.com/hive-corporation/watchtower/internal/adapter/handler"
	"github.com/hive-corporation/watchtower/internal/adapter/repository"
	pb "github.com/hive-corporation/watchtower/proto"
)

func main() {
	dbURL := "postgres://admin:secretpassword@localhost:5432/watchtower"
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

	s := grpc.NewServer()

	pb.RegisterWatchtowerServer(s, grpcHandler)

	reflection.Register(s)

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
