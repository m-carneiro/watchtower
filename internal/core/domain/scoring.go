package domain

// CalculateConfidenceScore calculates an overall confidence score from multiple IOC sightings.
// This is a pure domain function with no I/O dependencies.
//
// Current implementation: Returns 90 if multiple sources confirm the threat, 80 for single source.
// Future: Weight by source reputation, recency, tag presence.
func CalculateConfidenceScore(iocs []IOC) int32 {
	if len(iocs) == 0 {
		return 0
	}

	// Multiple sources increase confidence
	if len(iocs) >= 3 {
		return 90
	} else if len(iocs) >= 2 {
		return 85
	}

	// Single source
	return 80
}
