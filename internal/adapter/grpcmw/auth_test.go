package grpcmw

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestUnaryTokenAuthInterceptor(t *testing.T) {
	const token = "s3cr3t-grpc-token"

	okHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}
	interceptor := UnaryTokenAuthInterceptor(token)
	info := &grpc.UnaryServerInfo{FullMethod: "/watchtower.Watchtower/CheckIOC"}

	tests := []struct {
		name    string
		ctx     context.Context
		wantErr bool
	}{
		{
			name:    "valid token",
			ctx:     metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token)),
			wantErr: false,
		},
		{
			name:    "wrong token",
			ctx:     metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer nope")),
			wantErr: true,
		},
		{
			name:    "missing bearer prefix",
			ctx:     metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", token)),
			wantErr: true,
		},
		{
			name:    "no authorization header",
			ctx:     metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-other", "v")),
			wantErr: true,
		},
		{
			name:    "no metadata",
			ctx:     context.Background(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := interceptor(tc.ctx, nil, info, okHandler)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if status.Code(err) != codes.Unauthenticated {
					t.Fatalf("expected Unauthenticated, got %v", status.Code(err))
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp != "ok" {
				t.Fatalf("handler not invoked, resp = %v", resp)
			}
		})
	}
}
