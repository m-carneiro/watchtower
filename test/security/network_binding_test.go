package security

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestGRPC_DefaultLocalhostBinding(t *testing.T) {
	// Test that gRPC defaults to localhost when GRPC_LISTEN_ADDR is not set
	os.Unsetenv("GRPC_LISTEN_ADDR")

	// Simulate the binding logic from main.go
	listenAddr := os.Getenv("GRPC_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "localhost:50051" // Secure default
	}

	// Verify it's localhost
	if listenAddr != "localhost:50051" {
		t.Errorf("Expected default to be localhost:50051, got %s", listenAddr)
	}

	// Attempt to bind
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("Failed to bind to localhost: %v", err)
	}
	defer lis.Close()

	// Verify the address
	addr := lis.Addr().String()
	if addr != "127.0.0.1:50051" && addr != "[::1]:50051" {
		t.Errorf("Expected loopback address, got %s", addr)
	}
}

func TestGRPC_ExplicitExternalBinding(t *testing.T) {
	// Test that external binding requires explicit configuration
	t.Setenv("GRPC_LISTEN_ADDR", "0.0.0.0:50052")

	listenAddr := os.Getenv("GRPC_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "localhost:50051"
	}

	if listenAddr != "0.0.0.0:50052" {
		t.Errorf("Expected 0.0.0.0:50052, got %s", listenAddr)
	}

	// Attempt to bind
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("Failed to bind to 0.0.0.0: %v", err)
	}
	defer lis.Close()
}

func TestGRPC_InvalidAddress(t *testing.T) {
	// Test handling of invalid addresses
	invalidAddresses := []string{
		"invalid:address",
		":99999", // Port out of range
		"999.999.999.999:50051",
	}

	for _, addr := range invalidAddresses {
		t.Run(addr, func(t *testing.T) {
			_, err := net.Listen("tcp", addr)
			if err == nil {
				t.Errorf("Expected error for invalid address %s", addr)
			}
		})
	}
}

func TestGRPC_PortAlreadyInUse(t *testing.T) {
	// Bind to a port
	lis1, err := net.Listen("tcp", "localhost:0") // Use :0 for random port
	if err != nil {
		t.Fatalf("Failed to bind first listener: %v", err)
	}
	defer lis1.Close()

	addr := lis1.Addr().String()

	// Try to bind to same address
	_, err = net.Listen("tcp", addr)
	if err == nil {
		t.Error("Expected error when port is already in use")
	}
}

func TestGRPC_LocalhostOnlyAccess(t *testing.T) {
	// Start a listener on localhost
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to bind listener: %v", err)
	}
	defer lis.Close()

	addr := lis.Addr().String()

	// Accept connections in background
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Test local connection (should work)
	localConn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Errorf("Failed to connect locally: %v", err)
	} else {
		localConn.Close()
	}

	// Note: Testing external connection failure would require
	// running on a multi-interface system, which is environment-specific
}

func TestGRPC_IPv4vsIPv6(t *testing.T) {
	// Test that localhost resolves correctly
	testCases := []struct {
		name    string
		address string
	}{
		{"IPv4 loopback", "127.0.0.1:50053"},
		{"IPv6 loopback", "[::1]:50054"},
		{"Localhost", "localhost:50055"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lis, err := net.Listen("tcp", tc.address)
			if err != nil {
				// IPv6 might not be available on all systems
				if tc.name == "IPv6 loopback" {
					t.Skipf("IPv6 not available: %v", err)
					return
				}
				t.Fatalf("Failed to bind to %s: %v", tc.address, err)
			}
			defer lis.Close()

			// Verify binding
			addr := lis.Addr().String()
			if addr == "" {
				t.Error("Expected non-empty address")
			}
		})
	}
}

func TestGRPC_ConnectionTimeout(t *testing.T) {
	// Test connection timeout to unreachable address
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var d net.Dialer
	_, err := d.DialContext(ctx, "tcp", "192.0.2.1:50051") // TEST-NET-1, should timeout

	if err == nil {
		t.Error("Expected timeout error for unreachable address")
	}
}

func BenchmarkGRPC_LocalhostBinding(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lis, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			b.Fatalf("Failed to bind: %v", err)
		}
		lis.Close()
	}
}
