package main

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/hive-corporation/watchtower/internal/adapter/handler"
	"github.com/hive-corporation/watchtower/internal/adapter/llm"
	"github.com/hive-corporation/watchtower/internal/adapter/notifier"
	"github.com/hive-corporation/watchtower/internal/adapter/repository"
	"github.com/hive-corporation/watchtower/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	ctx := context.Background()

	// Database connection
	dbURL := config.GetEnv("DATABASE_URL", "postgres://admin:secretpassword@localhost:5432/watchtower")
	dbPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("❌ Failed to connect to database: %v", err)
	}
	defer dbPool.Close()

	// Repository
	repo := repository.NewPostgresRepository(dbPool)

	// Slack notifier (optional - only if token configured)
	var slackNotifier *notifier.SlackNotifier
	if slackToken := os.Getenv("SLACK_BOT_TOKEN"); slackToken != "" {
		slackNotifier = notifier.NewSlackNotifier(
			slackToken,
			config.GetEnv("SLACK_CHANNEL_SECURITY", "#security-alerts"),
			config.GetEnv("SLACK_MENTION_TEAM", "@security-team"),
		)
		log.Println("✅ Slack notifier enabled")
	} else {
		log.Println("⚠️  Slack notifier disabled (no SLACK_BOT_TOKEN)")
	}

	// Initialize LLM metrics
	llm.InitMetrics()
	log.Println("✅ Prometheus metrics initialized")

	// LLM triager (optional - only if enabled and API key configured)
	llmTriager := llm.NewLLMTriager()
	if llmTriager.IsEnabled() {
		log.Println("✅ LLM triaging enabled")
	} else {
		log.Println("⚠️  LLM triaging disabled (set LLM_TRIAGE_ENABLED=true and LLM_API_KEY)")
	}

	// HTTP router
	router := mux.NewRouter()

	// REST handler
	restHandler := handler.NewRestHandler(repo, slackNotifier, llmTriager)

	// Health check
	router.HandleFunc("/api/v1/health", restHandler.Health).Methods("GET")

	// IOC endpoints
	router.HandleFunc("/api/v1/iocs/check", restHandler.CheckIOC).Methods("GET")
	router.HandleFunc("/api/v1/iocs/search", restHandler.SearchIOC).Methods("GET")
	router.HandleFunc("/api/v1/iocs/feed", restHandler.GetIOCFeed).Methods("GET")

	// Webhook endpoints
	router.HandleFunc("/api/v1/webhooks/sentinelone", restHandler.SentinelOneWebhook).Methods("POST")

	// Metrics endpoint (requires authentication)
	router.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// Middleware
	router.Use(loggingMiddleware)
	router.Use(authMiddleware)

	// HTTP server
	port := config.GetEnv("REST_API_PORT", "8080")
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		log.Printf("🚀 Watchtower REST API listening on port %s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("❌ Server forced to shutdown: %v", err)
	}

	log.Println("✅ Server stopped gracefully")
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("→ %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
		log.Printf("← %s %s (%v)", r.Method, r.URL.Path, time.Since(start))
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Verify API token for all other endpoints (including /metrics)
		token := r.Header.Get("Authorization")
		expectedToken := os.Getenv("REST_API_AUTH_TOKEN")

		// Fail closed: refuse all requests if no token is configured.
		if expectedToken == "" {
			log.Println("❌ REST_API_AUTH_TOKEN not set - rejecting request (auth required)")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate Bearer token with a constant-time comparison to avoid
		// leaking the token via response-timing side channels.
		expected := "Bearer " + expectedToken
		if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
