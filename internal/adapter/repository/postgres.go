package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/hive-corporation/watchtower/internal/core/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	db *pgxpool.Pool
}

func NewPostgresRepository(db *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) SaveBatch(ctx context.Context, iocs []domain.IOC) error {
	batch := &pgx.Batch{}

	query := `
		INSERT INTO iocs (value, type, source, threat_type, tags, version, first_seen, date_ingested)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (value, source, version) DO NOTHING
	`

	for _, ioc := range iocs {
		batch.Queue(query,
			ioc.Value,
			ioc.Type,
			ioc.Source,
			ioc.ThreatType,
			ioc.Tags,
			ioc.Version,
			ioc.FirstSeen,
			ioc.DateIngested,
		)
	}

	br := r.db.SendBatch(ctx, batch)
	defer br.Close()

	_, err := br.Exec()
	if err != nil {
		return fmt.Errorf("failed to execute batch: %w", err)
	}

	return nil
}

func (r *PostgresRepository) FindByValue(ctx context.Context, value string) (*domain.IOC, error) {
	query := `
		SELECT value, type, source, threat_type, tags, version, first_seen, date_ingested
		FROM iocs
		WHERE value = $1
		LIMIT 1
	`

	var ioc domain.IOC

	err := r.db.QueryRow(ctx, query, value).Scan(
		&ioc.Value,
		&ioc.Type,
		&ioc.Source,
		&ioc.ThreatType,
		&ioc.Tags,
		&ioc.Version,
		&ioc.FirstSeen,
		&ioc.DateIngested,
	)

	if err != nil {
		return nil, err
	}

	return &ioc, nil
}

func (r *PostgresRepository) FindAllByValue(ctx context.Context, value string) ([]domain.IOC, error) {
	query := `
		SELECT value, type, source, threat_type, tags, version, first_seen, date_ingested
		FROM iocs
		WHERE value = $1
		ORDER BY date_ingested DESC
	`

	rows, err := r.db.Query(ctx, query, value)
	if err != nil {
		return nil, fmt.Errorf("failed to query IOCs: %w", err)
	}
	defer rows.Close()

	var iocs []domain.IOC

	for rows.Next() {
		var ioc domain.IOC
		err := rows.Scan(
			&ioc.Value,
			&ioc.Type,
			&ioc.Source,
			&ioc.ThreatType,
			&ioc.Tags,
			&ioc.Version,
			&ioc.FirstSeen,
			&ioc.DateIngested,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan IOC: %w", err)
		}
		iocs = append(iocs, ioc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return iocs, nil
}

func (r *PostgresRepository) FindByValueAndVersion(ctx context.Context, value, version string) ([]domain.IOC, error) {
	query := `
		SELECT value, type, source, threat_type, tags, version, first_seen, date_ingested
		FROM iocs
		WHERE value = $1 AND (version = $2 OR version = '')
		ORDER BY date_ingested DESC
	`

	rows, err := r.db.Query(ctx, query, value, version)
	if err != nil {
		return nil, fmt.Errorf("failed to query IOCs by version: %w", err)
	}
	defer rows.Close()

	var iocs []domain.IOC

	for rows.Next() {
		var ioc domain.IOC
		err := rows.Scan(
			&ioc.Value,
			&ioc.Type,
			&ioc.Source,
			&ioc.ThreatType,
			&ioc.Tags,
			&ioc.Version,
			&ioc.FirstSeen,
			&ioc.DateIngested,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan IOC: %w", err)
		}
		iocs = append(iocs, ioc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return iocs, nil
}

func (r *PostgresRepository) FindContaining(ctx context.Context, value string) ([]domain.IOC, error) {
	// Search for IOCs where the value CONTAINS the search term
	// Example: searching for "198.0.2.12" will find "http://198.0.2.12/malware.sh"
	query := `
		SELECT value, type, source, threat_type, tags, version, first_seen, date_ingested
		FROM iocs
		WHERE value LIKE '%' || $1 || '%'
		ORDER BY date_ingested DESC
		LIMIT 100
	`

	rows, err := r.db.Query(ctx, query, value)
	if err != nil {
		return nil, fmt.Errorf("failed to query IOCs with pattern: %w", err)
	}
	defer rows.Close()

	var iocs []domain.IOC

	for rows.Next() {
		var ioc domain.IOC
		err := rows.Scan(
			&ioc.Value,
			&ioc.Type,
			&ioc.Source,
			&ioc.ThreatType,
			&ioc.Tags,
			&ioc.Version,
			&ioc.FirstSeen,
			&ioc.DateIngested,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan IOC: %w", err)
		}
		iocs = append(iocs, ioc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return iocs, nil
}

func (r *PostgresRepository) FindSince(ctx context.Context, since time.Time, limit int) ([]domain.IOC, error) {
	query := `
		SELECT value, type, source, threat_type, tags, version, first_seen, date_ingested
		FROM iocs
		WHERE date_ingested >= $1
		ORDER BY date_ingested DESC
		LIMIT $2
	`

	rows, err := r.db.Query(ctx, query, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query IOCs since %v: %w", since, err)
	}
	defer rows.Close()

	var iocs []domain.IOC

	for rows.Next() {
		var ioc domain.IOC
		err := rows.Scan(
			&ioc.Value,
			&ioc.Type,
			&ioc.Source,
			&ioc.ThreatType,
			&ioc.Tags,
			&ioc.Version,
			&ioc.FirstSeen,
			&ioc.DateIngested,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan IOC: %w", err)
		}
		iocs = append(iocs, ioc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return iocs, nil
}
