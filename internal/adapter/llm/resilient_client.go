package llm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/sony/gobreaker"
)

// ResilientClient wraps an HTTP client with circuit breaker and retry logic
type ResilientClient struct {
	client  *http.Client
	breaker *gobreaker.CircuitBreaker
	config  ResilientClientConfig
}

// ResilientClientConfig holds configuration for the resilient client
type ResilientClientConfig struct {
	// Circuit breaker settings
	EnableCircuitBreaker bool
	MaxFailures          uint32
	CircuitTimeout       time.Duration

	// Retry settings
	MaxRetries      int
	InitialInterval time.Duration
	MaxInterval     time.Duration
}

// DefaultResilientClientConfig returns default configuration values
func DefaultResilientClientConfig() ResilientClientConfig {
	return ResilientClientConfig{
		EnableCircuitBreaker: getEnvBool("LLM_CIRCUIT_BREAKER_ENABLED", true),
		MaxFailures:          uint32(getEnvInt("LLM_CIRCUIT_BREAKER_MAX_FAILURES", 5)),
		CircuitTimeout:       time.Duration(getEnvInt("LLM_CIRCUIT_BREAKER_TIMEOUT_SECONDS", 30)) * time.Second,
		MaxRetries:           getEnvInt("LLM_RETRY_MAX_ATTEMPTS", 3),
		InitialInterval:      time.Duration(getEnvInt("LLM_RETRY_INITIAL_INTERVAL_MS", 500)) * time.Millisecond,
		MaxInterval:          time.Duration(getEnvInt("LLM_RETRY_MAX_INTERVAL_MS", 5000)) * time.Millisecond,
	}
}

// NewResilientClient creates a new resilient HTTP client
func NewResilientClient(timeout time.Duration, config ResilientClientConfig) *ResilientClient {
	client := &http.Client{
		Timeout: timeout,
	}

	var breaker *gobreaker.CircuitBreaker
	if config.EnableCircuitBreaker {
		settings := gobreaker.Settings{
			Name:        "llm-api",
			MaxRequests: 1,
			Interval:    0, // Don't reset counts automatically
			Timeout:     config.CircuitTimeout,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.ConsecutiveFailures >= config.MaxFailures
			},
			OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
				fmt.Printf("⚡ Circuit breaker '%s' changed from %s to %s\n", name, from, to)
				if to == gobreaker.StateOpen {
					RecordError("circuit_open")
				}
			},
		}
		breaker = gobreaker.NewCircuitBreaker(settings)
	}

	return &ResilientClient{
		client:  client,
		breaker: breaker,
		config:  config,
	}
}

// Do executes an HTTP request with circuit breaker and retry logic
func (c *ResilientClient) Do(req *http.Request) (*http.Response, error) {
	// If circuit breaker is disabled, just do the request with retry
	if c.breaker == nil {
		return c.doWithRetry(req)
	}

	// Execute through circuit breaker
	result, err := c.breaker.Execute(func() (interface{}, error) {
		return c.doWithRetry(req)
	})

	if err != nil {
		if errors.Is(err, gobreaker.ErrOpenState) {
			RecordError("circuit_open")
			return nil, fmt.Errorf("circuit breaker is open: %w", err)
		}
		return nil, err
	}

	return result.(*http.Response), nil
}

// doWithRetry executes an HTTP request with exponential backoff retry logic
func (c *ResilientClient) doWithRetry(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var lastErr error

	// If max retries is 0, just do a single attempt
	if c.config.MaxRetries == 0 {
		resp, err := c.client.Do(req)
		if err != nil {
			RecordError("connection")
			return nil, err
		}
		// Check for error status codes
		if resp.StatusCode >= 400 {
			c.recordErrorFromResponse(resp)
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
		}
		return resp, nil
	}

	// Configure exponential backoff
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = c.config.InitialInterval
	expBackoff.MaxInterval = c.config.MaxInterval
	expBackoff.Multiplier = 2.0
	expBackoff.MaxElapsedTime = 0 // No max elapsed time, only max retries

	// Wrap with max retries
	retryBackoff := backoff.WithMaxRetries(expBackoff, uint64(c.config.MaxRetries))

	// Create a context-aware backoff
	ctx := req.Context()
	retryBackoff = backoff.WithContext(retryBackoff, ctx)

	operation := func() error {
		// Clone request body for retry (if present)
		var bodyBytes []byte
		if req.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(req.Body)
			if err != nil {
				return backoff.Permanent(fmt.Errorf("failed to read request body: %w", err))
			}
			req.Body.Close()
		}

		// Create new request with body for this attempt
		if len(bodyBytes) > 0 {
			req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}

		var err error
		resp, err = c.client.Do(req)
		if err != nil {
			lastErr = err
			if c.shouldRetry(err, nil) {
				RecordError("connection")
				return err // Retry
			}
			RecordError("connection")
			return backoff.Permanent(err) // Don't retry
		}

		// Check if response indicates we should retry
		if c.shouldRetry(nil, resp) {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
			c.recordErrorFromResponse(resp)
			resp.Body.Close()
			return lastErr // Retry
		}

		// Success - record any API errors (e.g., 4xx)
		if resp.StatusCode >= 400 {
			c.recordErrorFromResponse(resp)
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
			return backoff.Permanent(lastErr) // Don't retry 4xx
		}

		return nil
	}

	err := backoff.Retry(operation, retryBackoff)
	if err != nil {
		return nil, fmt.Errorf("request failed after retries: %w", lastErr)
	}

	return resp, nil
}

// shouldRetry determines if an error or response should trigger a retry
func (c *ResilientClient) shouldRetry(err error, resp *http.Response) bool {
	// Retry on network errors or timeouts
	if err != nil {
		// Check for timeout
		if errors.Is(err, context.DeadlineExceeded) {
			return true
		}
		// Check for connection errors
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "EOF") {
			return true
		}
		return false
	}

	// Retry on specific HTTP status codes
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusTooManyRequests, // 429
			http.StatusServiceUnavailable,  // 503
			http.StatusGatewayTimeout,      // 504
			http.StatusBadGateway,          // 502
			http.StatusInternalServerError: // 500
			return true
		}
	}

	return false
}

// recordErrorFromResponse records the appropriate error metric based on response status
func (c *ResilientClient) recordErrorFromResponse(resp *http.Response) {
	if resp == nil {
		return
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		RecordError("auth")
	case http.StatusTooManyRequests:
		RecordError("rate_limit")
	case http.StatusRequestTimeout:
		RecordError("timeout")
	case http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		RecordError("server_error")
	default:
		RecordError("http_error")
	}
}

// getEnvInt reads an integer from environment variable or returns default
func getEnvInt(key string, defaultValue int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getEnvBool reads a boolean from environment variable or returns default
func getEnvBool(key string, defaultValue bool) bool {
	if val := os.Getenv(key); val != "" {
		if boolVal, err := strconv.ParseBool(val); err == nil {
			return boolVal
		}
	}
	return defaultValue
}
