package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SlackNotifier struct {
	botToken    string
	channel     string
	mentionTeam string
	httpClient  *http.Client
}

func NewSlackNotifier(botToken, channel, mentionTeam string) *SlackNotifier {
	return &SlackNotifier{
		botToken:    botToken,
		channel:     channel,
		mentionTeam: mentionTeam,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// NotifySentinelOneDetection sends formatted alert to Slack
func (s *SlackNotifier) NotifySentinelOneDetection(alert SentinelOneAlert, enriched []EnrichedIndicator) error {
	// Build Slack message blocks
	blocks := s.buildSentinelOneBlocks(alert, enriched)

	// Slack API payload
	payload := SlackMessage{
		Channel: s.channel,
		Blocks:  blocks,
		Text:    fmt.Sprintf("⚠️ Threat detected on %s", alert.Endpoint.ComputerName),
	}

	return s.sendMessage(payload)
}

// NotifyHighConfidenceIOC sends alert for new high-confidence IOCs
func (s *SlackNotifier) NotifyHighConfidenceIOC(ioc IOCNotification) error {
	blocks := s.buildHighConfidenceIOCBlocks(ioc)

	payload := SlackMessage{
		Channel: s.channel,
		Blocks:  blocks,
		Text:    fmt.Sprintf("🚨 High-confidence IOC detected: %s", ioc.Value),
	}

	return s.sendMessage(payload)
}

// NotifySupplyChainThreat sends alert for malicious packages
func (s *SlackNotifier) NotifySupplyChainThreat(pkg SupplyChainThreat) error {
	blocks := s.buildSupplyChainBlocks(pkg)

	payload := SlackMessage{
		Channel: s.channel,
		Blocks:  blocks,
		Text:    fmt.Sprintf("📦 Supply chain threat: %s", pkg.PackageName),
	}

	return s.sendMessage(payload)
}

// Build Slack message blocks for SentinelOne detection
func (s *SlackNotifier) buildSentinelOneBlocks(alert SentinelOneAlert, enriched []EnrichedIndicator) []SlackBlock {
	blocks := []SlackBlock{
		// Header
		{
			Type: "header",
			Text: &SlackText{
				Type: "plain_text",
				Text: "⚠️ Threat Detection Alert",
			},
		},
		// Alert details
		{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Endpoint*\n%s", alert.Endpoint.ComputerName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*OS Type*\n%s", alert.Endpoint.OSType)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Threat*\n%s", alert.ThreatName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Classification*\n%s", alert.Classification)},
			},
		},
		{
			Type: "divider",
		},
	}

	// IOC details
	for _, ind := range enriched {
		if ind.InDatabase {
			// Enriched IOC
			sourcesList := strings.Join(ind.Sources, ", ")
			tagsList := strings.Join(ind.Tags, ", ")

			blocks = append(blocks, SlackBlock{
				Type: "section",
				Text: &SlackText{
					Type: "mrkdwn",
					Text: fmt.Sprintf("*%s*: `%s`\n• Sources: %s\n• Tags: %s\n• First Seen: %s",
						ind.Type, ind.Value, sourcesList, tagsList, ind.FirstSeen.Format("2006-01-02")),
				},
			})
		} else {
			// Not in Watchtower database
			blocks = append(blocks, SlackBlock{
				Type: "section",
				Text: &SlackText{
					Type: "mrkdwn",
					Text: fmt.Sprintf("*%s*: `%s`\n_Not found in Watchtower database_", ind.Type, ind.Value),
				},
			})
		}
	}

	// Recommended actions
	blocks = append(blocks,
		SlackBlock{Type: "divider"},
		SlackBlock{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*Recommended Actions*\n✓ Isolate endpoint %s\n✓ Investigate recent activity\n✓ Scan other endpoints\n\ncc: %s",
					alert.Endpoint.ComputerName, s.mentionTeam),
			},
		},
	)

	return blocks
}

// Build Slack blocks for high-confidence IOC
func (s *SlackNotifier) buildHighConfidenceIOCBlocks(ioc IOCNotification) []SlackBlock {
	return []SlackBlock{
		{
			Type: "header",
			Text: &SlackText{
				Type: "plain_text",
				Text: "🚨 High-Confidence IOC Detected",
			},
		},
		{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Value*\n`%s`", ioc.Value)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Type*\n%s", ioc.Type)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Confidence*\n%d/100", ioc.Confidence)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Sources*\n%s", strings.Join(ioc.Sources, ", "))},
			},
		},
		{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*Tags*: %s\n\ncc: %s", strings.Join(ioc.Tags, ", "), s.mentionTeam),
			},
		},
	}
}

// Build Slack blocks for supply chain threat
func (s *SlackNotifier) buildSupplyChainBlocks(pkg SupplyChainThreat) []SlackBlock {
	versionText := pkg.Version
	if versionText == "" {
		versionText = "All versions"
	}

	return []SlackBlock{
		{
			Type: "header",
			Text: &SlackText{
				Type: "plain_text",
				Text: "📦 Supply Chain Threat Detected",
			},
		},
		{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Package*\n`%s`", pkg.PackageName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Version*\n%s", versionText)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Ecosystem*\n%s", pkg.Ecosystem)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Source*\n%s", pkg.Source)},
			},
		},
		{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*Threat Type*: %s\n*Tags*: %s\n\n🔒 *Action Required*: Block this package in CI/CD pipelines\n\ncc: %s @devops",
					pkg.ThreatType, strings.Join(pkg.Tags, ", "), s.mentionTeam),
			},
		},
	}
}

// Send message to Slack
func (s *SlackNotifier) sendMessage(msg SlackMessage) error {
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	req, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.botToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack API returned status %d", resp.StatusCode)
	}

	return nil
}

// Slack API structures

type SlackMessage struct {
	Channel string       `json:"channel"`
	Blocks  []SlackBlock `json:"blocks"`
	Text    string       `json:"text"` // Fallback text
}

type SlackBlock struct {
	Type     string      `json:"type"`
	Text     *SlackText  `json:"text,omitempty"`
	Fields   []SlackText `json:"fields,omitempty"`
	Elements []SlackText `json:"elements,omitempty"`
}

type SlackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Notification data structures

type SentinelOneAlert struct {
	AlertID        string
	ThreatName     string
	Classification string
	Endpoint       struct {
		ComputerName string
		OSType       string
	}
}

type EnrichedIndicator struct {
	Type        string
	Value       string
	InDatabase  bool
	Sources     []string
	Tags        []string
	ThreatTypes []string
	FirstSeen   time.Time
}

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

// NotifySentinelOneDetectionWithTriage sends alert with LLM analysis
func (s *SlackNotifier) NotifySentinelOneDetectionWithTriage(alert SentinelOneAlert, enriched []EnrichedIndicator, triageResult *TriageResult) error {
	// Build Slack message blocks with LLM insights
	blocks := s.buildSentinelOneBlocksWithTriage(alert, enriched, triageResult)

	// Slack API payload
	payload := SlackMessage{
		Channel: s.channel,
		Blocks:  blocks,
		Text:    fmt.Sprintf("⚠️ %s: Threat detected on %s", strings.ToUpper(triageResult.Severity), alert.Endpoint.ComputerName),
	}

	return s.sendMessage(payload)
}

// Build Slack message blocks with LLM triaging results
func (s *SlackNotifier) buildSentinelOneBlocksWithTriage(alert SentinelOneAlert, enriched []EnrichedIndicator, triage *TriageResult) []SlackBlock {
	// Choose emoji based on severity
	severityEmoji := map[string]string{
		"critical": "🔴",
		"high":     "🟠",
		"medium":   "🟡",
		"low":      "🟢",
		"info":     "🔵",
	}
	emoji := severityEmoji[triage.Severity]
	if emoji == "" {
		emoji = "⚠️"
	}

	blocks := []SlackBlock{
		// Header with severity
		{
			Type: "header",
			Text: &SlackText{
				Type: "plain_text",
				Text: fmt.Sprintf("%s %s Severity Threat Detected", emoji, strings.ToUpper(triage.Severity)),
			},
		},

		// LLM Summary
		{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*🤖 AI Analysis*\n%s", triage.Summary),
			},
		},

		// Alert details
		{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Alert ID*\n%s", alert.AlertID)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Threat*\n%s", alert.ThreatName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Endpoint*\n%s", alert.Endpoint.ComputerName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Priority*\nP%d", triage.Priority)},
			},
		},

		{Type: "divider"},

		// Detailed analysis
		{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*📊 Detailed Analysis*\n%s", triage.Analysis),
			},
		},

		{Type: "divider"},

		// IOC details
		{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: "*🔍 Indicators of Compromise*",
			},
		},
	}

	// Add IOC details
	for i, ind := range enriched {
		if i >= 5 { // Limit to 5 IOCs to avoid message being too long
			blocks = append(blocks, SlackBlock{
				Type: "section",
				Text: &SlackText{
					Type: "mrkdwn",
					Text: fmt.Sprintf("_...and %d more indicators_", len(enriched)-5),
				},
			})
			break
		}

		iocText := fmt.Sprintf("*%s:* `%s`", ind.Type, ind.Value)

		if ind.InDatabase {
			iocText += fmt.Sprintf("\n• *Found in threat intel* ✅\n• Sources: %s",
				strings.Join(ind.Sources, ", "))

			if len(ind.ThreatTypes) > 0 {
				iocText += fmt.Sprintf("\n• Threat Types: %s", strings.Join(ind.ThreatTypes, ", "))
			}
		} else {
			iocText += "\n• Not found in threat database ⚠️"
		}

		blocks = append(blocks, SlackBlock{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: iocText,
			},
		})
	}

	blocks = append(blocks, SlackBlock{Type: "divider"})

	// Recommended actions
	if len(triage.Recommended) > 0 {
		recommendedText := "*✅ Recommended Actions*\n"
		for _, action := range triage.Recommended {
			recommendedText += fmt.Sprintf("• %s\n", action)
		}

		blocks = append(blocks, SlackBlock{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: recommendedText,
			},
		})
	}

	// Confidence footer
	confidenceEmoji := "🟢"
	if triage.Confidence < 70 {
		confidenceEmoji = "🟡"
	}
	if triage.Confidence < 50 {
		confidenceEmoji = "🔴"
	}

	blocks = append(blocks, SlackBlock{
		Type: "context",
		Elements: []SlackText{
			{
				Type: "mrkdwn",
				Text: fmt.Sprintf("%s AI Confidence: *%d%%* | Classification: *%s* | OS: *%s*",
					confidenceEmoji, triage.Confidence, alert.Classification, alert.Endpoint.OSType),
			},
		},
	})

	// Mention team if configured
	if s.mentionTeam != "" {
		blocks = append(blocks, SlackBlock{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("🔔 %s", s.mentionTeam),
			},
		})
	}

	return blocks
}

// TriageResult struct for LLM triaging results
type TriageResult struct {
	Severity      string
	Priority      int
	Summary       string
	Analysis      string
	Recommended   []string
	FalsePositive bool
	Confidence    int
}
