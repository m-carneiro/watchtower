package ports

import (
	"context"
	"time"

	"github.com/hive-corporation/watchtower/internal/core/domain"
)

type ThreatProvider interface {
	FetchIOCS(ctx context.Context) ([]domain.IOC, error)
	Name() string
}

type IOCRepository interface {
	SaveBatch(ctx context.Context, iocs []domain.IOC) error
	FindByValue(ctx context.Context, value string) (*domain.IOC, error)
	FindAllByValue(ctx context.Context, value string) ([]domain.IOC, error)
	FindByValueAndVersion(ctx context.Context, value, version string) ([]domain.IOC, error)
	FindContaining(ctx context.Context, value string) ([]domain.IOC, error)
	FindSince(ctx context.Context, since time.Time, limit int) ([]domain.IOC, error)
}
