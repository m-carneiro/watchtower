package llm

import (
	"crypto/sha256"
	"encoding/hex"
)

// RedactEndpoint returns a stable, non-identifying pseudonym for an internal
// endpoint identifier (e.g. a hostname). It is used to avoid leaking internal
// asset names to external LLM providers during triage.
//
// The mapping is deterministic, so the same host always yields the same
// pseudonym (alerts remain correlatable), but it is one-way and carries no
// information about the original name.
func RedactEndpoint(name string) string {
	if name == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(name))
	return "endpoint-" + hex.EncodeToString(sum[:])[:8]
}
