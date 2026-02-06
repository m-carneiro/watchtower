package domain

import (
	"net"
	"net/url"
	"strings"
)

// ExtractIOCComponents extracts multiple IOCs from a complex value
// For example, "http://198.0.2.12/malware.sh" produces:
// - Full URL IOC
// - IP address IOC
// - Domain IOC (if hostname is domain)
func ExtractIOCComponents(value string, sourceIOC IOC) []IOC {
	components := []IOC{sourceIOC} // Always include the original

	// Try to parse as URL
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if u, err := url.Parse(value); err == nil {
			// Extract host (IP or domain)
			host := u.Hostname()
			if host != "" && host != value {
				// Determine if it's an IP or domain
				if net.ParseIP(host) != nil {
					// It's an IP address
					components = append(components, IOC{
						Value:        host,
						Type:         IPAddress,
						Source:       sourceIOC.Source,
						ThreatType:   sourceIOC.ThreatType,
						Tags:         append([]string{"extracted-from-url"}, sourceIOC.Tags...),
						Version:      "",
						FirstSeen:    sourceIOC.FirstSeen,
						DateIngested: sourceIOC.DateIngested,
					})
				} else {
					// It's a domain
					components = append(components, IOC{
						Value:        host,
						Type:         Domain,
						Source:       sourceIOC.Source,
						ThreatType:   sourceIOC.ThreatType,
						Tags:         append([]string{"extracted-from-url"}, sourceIOC.Tags...),
						Version:      "",
						FirstSeen:    sourceIOC.FirstSeen,
						DateIngested: sourceIOC.DateIngested,
					})
				}
			}
		}
	}

	// Check if the value itself looks like an IP embedded in something
	// Example: "198.0.2.12:8080" or "198.0.2.12/path"
	if !strings.HasPrefix(value, "http") {
		parts := strings.FieldsFunc(value, func(r rune) bool {
			return r == ':' || r == '/' || r == '?'
		})

		for _, part := range parts {
			if net.ParseIP(part) != nil && part != value {
				components = append(components, IOC{
					Value:        part,
					Type:         IPAddress,
					Source:       sourceIOC.Source,
					ThreatType:   sourceIOC.ThreatType,
					Tags:         append([]string{"extracted-from-value"}, sourceIOC.Tags...),
					Version:      "",
					FirstSeen:    sourceIOC.FirstSeen,
					DateIngested: sourceIOC.DateIngested,
				})
				break // Only extract the first IP found
			}
		}
	}

	return components
}

// NormalizeIOCValue normalizes IOC values for better matching
func NormalizeIOCValue(value string, iocType IOCType) string {
	switch iocType {
	case URL:
		// Normalize URL (lowercase, remove trailing slash)
		value = strings.ToLower(value)
		value = strings.TrimSuffix(value, "/")
		return value

	case Domain:
		// Lowercase domain
		return strings.ToLower(value)

	case IPAddress:
		// Trim whitespace
		return strings.TrimSpace(value)

	default:
		return value
	}
}
