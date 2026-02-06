package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// TriageResult contains the LLM's analysis of the threat
type TriageResult struct {
	Severity      string   `json:"severity"`       // critical, high, medium, low, info
	Priority      int      `json:"priority"`       // 1-5 (1 = highest)
	Summary       string   `json:"summary"`        // Brief summary of the threat
	Analysis      string   `json:"analysis"`       // Detailed analysis
	Recommended   []string `json:"recommended"`    // Recommended actions
	FalsePositive bool     `json:"false_positive"` // Whether it's likely a false positive
	Confidence    int      `json:"confidence"`     // Confidence in the assessment (0-100)
}

// ThreatContext contains information about the threat to be analyzed
type ThreatContext struct {
	AlertID        string
	ThreatName     string
	Classification string
	Endpoint       string
	OSType         string
	IOCs           []IOCContext
}

// IOCContext contains information about an enriched IOC
type IOCContext struct {
	Type        string
	Value       string
	InDatabase  bool
	Sources     []string
	Tags        []string
	ThreatTypes []string
	FirstSeen   time.Time
}

// LLMTriager uses LLM to analyze and triage security threats
type LLMTriager struct {
	apiURL  string
	apiKey  string
	model   string
	client  *ResilientClient
	enabled bool
}

// NewLLMTriager creates a new LLM triager
func NewLLMTriager() *LLMTriager {
	apiKey := os.Getenv("LLM_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY") // Fallback to OPENAI_API_KEY
	}

	enabled := os.Getenv("LLM_TRIAGE_ENABLED")

	// Default to LiteLLM proxy (supports multiple providers)
	apiURL := os.Getenv("LLM_API_URL")
	if apiURL == "" {
		apiURL = "https://api.openai.com/v1/chat/completions" // Default to OpenAI
	}

	model := os.Getenv("LLM_MODEL")
	if model == "" {
		model = "gpt-4o-mini" // Fast and cost-effective
	}

	// Create resilient client with circuit breaker and retry logic
	config := DefaultResilientClientConfig()
	client := NewResilientClient(30*time.Second, config)

	return &LLMTriager{
		apiURL:  apiURL,
		apiKey:  apiKey,
		model:   model,
		client:  client,
		enabled: enabled == "true" && apiKey != "",
	}
}

// IsEnabled returns whether LLM triaging is enabled
func (t *LLMTriager) IsEnabled() bool {
	return t.enabled
}

// Triage analyzes the threat context and returns a triaging decision
func (t *LLMTriager) Triage(ctx context.Context, threat ThreatContext) (*TriageResult, error) {
	// Start timer for metrics
	timer := StartTimer()
	defer timer.ObserveDuration()

	if !t.enabled {
		return nil, fmt.Errorf("LLM triaging is not enabled")
	}

	// Apply pre-LLM guardrails (rule-based filters)
	config := DefaultGuardrailConfig()
	if preResult, shouldSkip := ApplyPreLLMGuardrails(threat, config); shouldSkip {
		// Record that we skipped the LLM call due to pre-filter
		RecordTriageRequest("skipped", "pre_filter")
		RecordResult(preResult)
		if preResult.FalsePositive {
			RecordFalsePositive()
		}
		return preResult, nil
	}

	// Build the prompt
	prompt := t.buildPrompt(threat)

	// Call LLM API
	response, err := t.callLLM(ctx, prompt)
	if err != nil {
		RecordTriageRequest("error", "llm")
		// Try to classify the error type
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			RecordError("timeout")
		} else if strings.Contains(err.Error(), "circuit breaker") {
			RecordError("circuit_open")
		} else if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") {
			RecordError("auth")
		} else {
			RecordError("parse")
		}
		return nil, fmt.Errorf("failed to call LLM: %w", err)
	}

	// Parse the response
	result, err := t.parseResponse(response)
	if err != nil {
		RecordTriageRequest("error", "parse")
		RecordError("parse")
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	// Apply post-LLM guardrails (validation and adjustment)
	result = ApplyPostLLMGuardrails(result, threat, config)

	// Record successful triage
	RecordTriageRequest("success", "llm")
	RecordResult(result)
	if result.FalsePositive {
		RecordFalsePositive()
	}

	return result, nil
}

func (t *LLMTriager) buildPrompt(threat ThreatContext) string {
	var sb strings.Builder

	sb.WriteString("You are a cybersecurity analyst reviewing a security alert. Analyze the following threat and provide a structured assessment.\n\n")

	// Alert Information
	sb.WriteString(fmt.Sprintf("**Alert ID:** %s\n", threat.AlertID))
	sb.WriteString(fmt.Sprintf("**Threat Name:** %s\n", threat.ThreatName))
	sb.WriteString(fmt.Sprintf("**Classification:** %s\n", threat.Classification))
	sb.WriteString(fmt.Sprintf("**Endpoint:** %s (%s)\n\n", threat.Endpoint, threat.OSType))

	// IOC Information
	sb.WriteString("**Indicators of Compromise (IOCs):**\n")
	for i, ioc := range threat.IOCs {
		sb.WriteString(fmt.Sprintf("%d. Type: %s, Value: %s\n", i+1, ioc.Type, ioc.Value))

		if ioc.InDatabase {
			sb.WriteString("   - Found in threat intelligence database\n")
			if len(ioc.Sources) > 0 {
				sb.WriteString(fmt.Sprintf("   - Sources: %s\n", strings.Join(ioc.Sources, ", ")))
			}
			if len(ioc.ThreatTypes) > 0 {
				sb.WriteString(fmt.Sprintf("   - Threat Types: %s\n", strings.Join(ioc.ThreatTypes, ", ")))
			}
			if len(ioc.Tags) > 0 {
				sb.WriteString(fmt.Sprintf("   - Tags: %s\n", strings.Join(ioc.Tags[:min(5, len(ioc.Tags))], ", ")))
			}
			if !ioc.FirstSeen.IsZero() {
				sb.WriteString(fmt.Sprintf("   - First Seen: %s\n", ioc.FirstSeen.Format("2006-01-02")))
			}
		} else {
			sb.WriteString("   - Not found in threat intelligence database\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\n**Task:**\n")
	sb.WriteString("Analyze this threat and provide your assessment in the following JSON format:\n")
	sb.WriteString("```json\n")
	sb.WriteString("{\n")
	sb.WriteString("  \"severity\": \"critical|high|medium|low|info\",\n")
	sb.WriteString("  \"priority\": 1-5,\n")
	sb.WriteString("  \"summary\": \"Brief one-sentence summary\",\n")
	sb.WriteString("  \"analysis\": \"Detailed analysis of the threat\",\n")
	sb.WriteString("  \"recommended\": [\"action1\", \"action2\"],\n")
	sb.WriteString("  \"false_positive\": true/false,\n")
	sb.WriteString("  \"confidence\": 0-100\n")
	sb.WriteString("}\n")
	sb.WriteString("```\n\n")

	sb.WriteString("**Important Guidelines:**\n")
	sb.WriteString("1. IOCs found in threat intelligence databases are STRONG evidence of malicious activity\n")
	sb.WriteString("2. Multiple threat intel sources confirming the same IOC = HIGH confidence\n")
	sb.WriteString("3. Known threat types (c2_server, botnet, ransomware, malware_download) = Real threat\n")
	sb.WriteString("4. Be conservative with false_positive=true - only use when VERY confident\n")
	sb.WriteString("5. IOCs NOT in database but suspicious behavior = medium severity, lower confidence\n\n")

	sb.WriteString("**Example 1 - Real Threat:**\n")
	sb.WriteString("IOC: 192.0.2.1 found in database, Sources: alienvault-otx, urlhaus, Threat Types: c2_server, botnet\n")
	sb.WriteString("→ severity: \"high\", false_positive: false, confidence: 95\n\n")

	sb.WriteString("**Example 2 - Likely False Positive:**\n")
	sb.WriteString("IOC: update.microsoft.com, NOT in database, Threat: \"Suspicious DNS\"\n")
	sb.WriteString("→ severity: \"info\", false_positive: true, confidence: 90\n\n")

	sb.WriteString("**Example 3 - Uncertain:**\n")
	sb.WriteString("IOC: unknown-domain.com, NOT in database, Threat: \"Suspicious Connection\"\n")
	sb.WriteString("→ severity: \"medium\", false_positive: false, confidence: 60\n\n")

	sb.WriteString("Now analyze the alert above and provide your assessment.\n")

	return sb.String()
}

func (t *LLMTriager) callLLM(ctx context.Context, prompt string) (string, error) {
	// Build request body
	requestBody := map[string]interface{}{
		"model": t.model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are an expert cybersecurity analyst. Analyze threats and provide structured assessments in JSON format.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.3, // Lower temperature for more consistent analysis
		"max_tokens":  1000,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", t.apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.apiKey))

	// Send request
	resp, err := t.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("LLM API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no choices in LLM response")
	}

	return response.Choices[0].Message.Content, nil
}

func (t *LLMTriager) parseResponse(response string) (*TriageResult, error) {
	// Extract JSON from markdown code blocks if present
	jsonStr := response
	if idx := strings.Index(response, "```json"); idx != -1 {
		jsonStr = response[idx+7:]
		if endIdx := strings.Index(jsonStr, "```"); endIdx != -1 {
			jsonStr = jsonStr[:endIdx]
		}
	} else if idx := strings.Index(response, "```"); idx != -1 {
		jsonStr = response[idx+3:]
		if endIdx := strings.Index(jsonStr, "```"); endIdx != -1 {
			jsonStr = jsonStr[:endIdx]
		}
	}

	jsonStr = strings.TrimSpace(jsonStr)

	var result TriageResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w (response: %s)", err, jsonStr)
	}

	return &result, nil
}
