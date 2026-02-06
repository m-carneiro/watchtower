package ports

// Notifier defines the interface for sending notifications to external systems
type Notifier interface {
	// NotifyHighConfidenceIOC sends notification for new high-confidence IOCs
	NotifyHighConfidenceIOC(ioc IOCNotification) error

	// NotifySupplyChainThreat sends notification for malicious packages
	NotifySupplyChainThreat(pkg SupplyChainThreat) error

	// NotifySentinelOneDetection sends notification for SentinelOne threat detections
	NotifySentinelOneDetection(alert SentinelOneAlert, enriched []EnrichedIndicator) error
}

// Notification data structures

type IOCNotification struct {
	Value      string
	Type       string
	Confidence int
	Sources    []string
	Tags       []string
}

type SupplyChainThreat struct {
	PackageName string
	Version     string
	Ecosystem   string
	Source      string
	ThreatType  string
	Tags        []string
}

type SentinelOneAlert struct {
	AlertID        string
	ThreatName     string
	Classification string
	Endpoint       EndpointInfo
	Timestamp      string
}

type EndpointInfo struct {
	ComputerName string
	OSType       string
	AgentVersion string
}

type EnrichedIndicator struct {
	Type        string
	Value       string
	InDatabase  bool
	Sources     []string
	Tags        []string
	ThreatTypes []string
}
