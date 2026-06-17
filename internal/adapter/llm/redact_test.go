package llm

import (
	"strings"
	"testing"
)

func TestRedactEndpoint(t *testing.T) {
	const host = "FIN-LAPTOP-042"

	got := RedactEndpoint(host)

	// Stable: same input -> same output.
	if again := RedactEndpoint(host); got != again {
		t.Fatalf("not stable: %q != %q", got, again)
	}

	// Non-identifying: original name must not leak.
	if strings.Contains(got, host) {
		t.Fatalf("pseudonym %q leaks original hostname", got)
	}

	if !strings.HasPrefix(got, "endpoint-") {
		t.Fatalf("unexpected prefix: %q", got)
	}

	// Different hosts -> different pseudonyms.
	if RedactEndpoint("OTHER-HOST") == got {
		t.Fatal("collision between distinct hostnames")
	}

	// Empty stays empty.
	if RedactEndpoint("") != "" {
		t.Fatal("empty input should map to empty string")
	}
}
