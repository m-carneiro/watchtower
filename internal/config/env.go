// Package config provides small shared helpers for reading configuration
// from the environment with sensible defaults.
package config

import "os"

// GetEnv returns the value of the environment variable named by key,
// or defaultValue if the variable is unset or empty.
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
