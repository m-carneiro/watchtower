package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hive-corporation/watchtower/internal/core/domain"
	"github.com/hive-corporation/watchtower/internal/core/ports"
	pb "github.com/hive-corporation/watchtower/proto"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type GrpcServer struct {
	pb.UnimplementedWatchtowerServer
	repo ports.IOCRepository
}

func NewGrpcServer(repo ports.IOCRepository) *GrpcServer {
	return &GrpcServer{
		repo: repo,
	}
}

func (s *GrpcServer) CheckIOC(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	if req.Value == "" {
		return nil, errors.New("value cannot be empty")
	}

	ioc, err := s.repo.FindByValue(ctx, req.Value)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Não encontrou = Não é ameaça (por enquanto)
			return &pb.CheckResponse{
				Exists:      false,
				ActionBlock: false,
			}, nil
		}
		log.Printf("❌ error checking IOC: %v", err)
		return nil, err
	}

	// 2. Encontrou! Mapeia para a resposta gRPC
	return &pb.CheckResponse{
		Exists:          true,
		ThreatType:      ioc.ThreatType,
		ConfidenceScore: 80,
		ActionBlock:     true,
	}, nil
}

func (s *GrpcServer) SearchIOC(ctx context.Context, req *pb.SearchRequest) (*pb.IOCDetails, error) {
	// 1. Validate request
	if req.Value == "" {
		return nil, errors.New("value cannot be empty")
	}

	// 2. Parse package@version format if present
	pkgName, version := parsePackageVersion(req.Value)

	// 3. Fetch IOCs based on whether version was specified
	var iocs []domain.IOC
	var err error

	if version != "" {
		// Version-specific query: find exact version or wildcard entries
		iocs, err = s.repo.FindByValueAndVersion(ctx, pkgName, version)
	} else {
		// No version: return all versions
		iocs, err = s.repo.FindAllByValue(ctx, pkgName)
	}

	if err != nil {
		log.Printf("❌ error searching IOCs: %v", err)
		return nil, err
	}

	// 3. If no IOCs found, return empty details
	if len(iocs) == 0 {
		return &pb.IOCDetails{
			Value:     req.Value,
			Sightings: []*pb.Sighting{},
		}, nil
	}

	// 4. Aggregate data from all IOCs
	details := &pb.IOCDetails{
		Value:        req.Value,
		Type:         string(iocs[0].Type), // Use type from first IOC
		OverallScore: domain.CalculateConfidenceScore(iocs),
		AllTags:      collectUniqueTags(iocs),
		FirstSeen:    timestamppb.New(findEarliestTimestamp(iocs)),
		LastSeen:     timestamppb.New(findLatestTimestamp(iocs)),
		Sightings:    buildSightings(iocs),
	}

	return details, nil
}

// collectUniqueTags aggregates all unique tags from multiple IOCs
func collectUniqueTags(iocs []domain.IOC) []string {
	tagSet := make(map[string]bool)
	for _, ioc := range iocs {
		for _, tag := range ioc.Tags {
			tagSet[tag] = true
		}
	}

	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	return tags
}

// findEarliestTimestamp finds the earliest FirstSeen timestamp
func findEarliestTimestamp(iocs []domain.IOC) time.Time {
	if len(iocs) == 0 {
		return time.Now()
	}

	earliest := iocs[0].FirstSeen
	for _, ioc := range iocs[1:] {
		if ioc.FirstSeen.Before(earliest) {
			earliest = ioc.FirstSeen
		}
	}
	return earliest
}

// findLatestTimestamp finds the latest DateIngested timestamp
func findLatestTimestamp(iocs []domain.IOC) time.Time {
	if len(iocs) == 0 {
		return time.Now()
	}

	latest := iocs[0].DateIngested
	for _, ioc := range iocs[1:] {
		if ioc.DateIngested.After(latest) {
			latest = ioc.DateIngested
		}
	}
	return latest
}

// buildSightings creates Sighting messages from IOCs with external links
func buildSightings(iocs []domain.IOC) []*pb.Sighting {
	sightings := make([]*pb.Sighting, 0, len(iocs))

	for _, ioc := range iocs {
		sighting := &pb.Sighting{
			Source:       ioc.Source,
			ThreatType:   ioc.ThreatType,
			DateIngested: timestamppb.New(ioc.DateIngested),
			ExternalLink: buildExternalLink(ioc),
		}
		sightings = append(sightings, sighting)
	}

	return sightings
}

// buildExternalLink constructs source-specific URLs for external references
func buildExternalLink(ioc domain.IOC) string {
	// Extract ID from tags for OSV entries
	if strings.HasPrefix(ioc.Source, "google-osv-") {
		for _, tag := range ioc.Tags {
			if strings.HasPrefix(tag, "GHSA-") || strings.HasPrefix(tag, "MAL-") || strings.HasPrefix(tag, "GO-") {
				return fmt.Sprintf("https://osv.dev/vulnerability/%s", tag)
			}
		}
		return "https://osv.dev"
	}

	// URLhaus links
	if ioc.Source == "abusech-urlhaus" {
		return fmt.Sprintf("https://urlhaus.abuse.ch/url/%s", ioc.Value)
	}

	// AlienVault OTX links
	if ioc.Source == "alienvault-otx" {
		return "https://otx.alienvault.com"
	}

	// Default: no specific link
	return ""
}

// parsePackageVersion splits "package@version" into (package, version)
// Returns (package, "") if no @ symbol found
func parsePackageVersion(value string) (string, string) {
	// Split on last @ to handle scoped packages like @org/package@1.0.0
	lastAt := strings.LastIndex(value, "@")
	if lastAt == -1 {
		return value, ""
	}

	// Special case: scoped npm packages start with @
	// @org/package@1.0.0 should split into (@org/package, 1.0.0)
	if strings.HasPrefix(value, "@") && lastAt == 0 {
		return value, "" // No version, just a scoped package name
	}

	pkgName := value[:lastAt]
	version := value[lastAt+1:]

	return pkgName, version
}
