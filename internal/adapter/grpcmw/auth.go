// Package grpcmw provides gRPC server middleware and transport security
// helpers (token authentication and TLS/mTLS credentials).
package grpcmw

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// UnaryTokenAuthInterceptor returns a gRPC unary interceptor that requires an
// "authorization: Bearer <token>" metadata entry. The comparison is done in
// constant time to avoid leaking the token through timing side channels.
func UnaryTokenAuthInterceptor(token string) grpc.UnaryServerInterceptor {
	expected := "Bearer " + token
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !validToken(ctx, expected) {
			return nil, status.Error(codes.Unauthenticated, "invalid or missing authorization token")
		}
		return handler(ctx, req)
	}
}

func validToken(ctx context.Context, expected string) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return false
	}
	got := strings.TrimSpace(vals[0])
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}
