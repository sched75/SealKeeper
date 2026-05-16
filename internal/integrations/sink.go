package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Event is the canonical shape forwarded to every Sink. It mirrors the
// audit_log row plus instance metadata that helps downstream SIEMs route
// the event correctly.
type Event struct {
	SequenceNo     int64           `json:"sequence_no"`
	OccurredAt     time.Time       `json:"occurred_at"`
	EventType      string          `json:"event_type"`
	Actor          string          `json:"actor,omitempty"`
	Target         string          `json:"target,omitempty"`
	Details        json.RawMessage `json:"details,omitempty"`
	EntryHash      string          `json:"entry_hash,omitempty"`
	InstanceDomain string          `json:"instance_domain"`
	Source         string          `json:"source"` // always "sealkeeper"
}

// NewEvent builds an Event with the common envelope fields populated.
func NewEvent(seq int64, eventType, actor, target string, details json.RawMessage,
	entryHash, instance string, occurred time.Time) Event {
	return Event{
		SequenceNo:     seq,
		OccurredAt:     occurred.UTC(),
		EventType:      eventType,
		Actor:          actor,
		Target:         target,
		Details:        details,
		EntryHash:      entryHash,
		InstanceDomain: instance,
		Source:         "sealkeeper",
	}
}

// Sink is the only interface the dispatcher cares about.
type Sink interface {
	Name() string
	Kind() Kind
	Send(ctx context.Context, ev Event) error
}

// BuildSink returns a Sink for the given Integration row. Returns
// ErrInvalidKind for unknown kinds and ErrInvalidConfig when the row's
// config_json cannot be parsed.
func BuildSink(row Integration) (Sink, error) {
	switch row.Kind {
	case KindWebhook:
		var cfg WebhookConfig
		if err := unmarshalConfig(row.ConfigJSON, &cfg); err != nil {
			return nil, err
		}
		return newWebhookSink(row.Name, cfg), nil

	case KindSplunk:
		var cfg SplunkConfig
		if err := unmarshalConfig(row.ConfigJSON, &cfg); err != nil {
			return nil, err
		}
		return newSplunkSink(row.Name, cfg), nil

	case KindSentinel:
		var cfg SentinelConfig
		if err := unmarshalConfig(row.ConfigJSON, &cfg); err != nil {
			return nil, err
		}
		return newSentinelSink(row.Name, cfg), nil

	case KindElastic:
		var cfg ElasticConfig
		if err := unmarshalConfig(row.ConfigJSON, &cfg); err != nil {
			return nil, err
		}
		return newElasticSink(row.Name, cfg), nil

	case KindSyslog:
		var cfg SyslogConfig
		if err := unmarshalConfig(row.ConfigJSON, &cfg); err != nil {
			return nil, err
		}
		return newSyslogSink(row.Name, cfg), nil

	default:
		return nil, fmt.Errorf("%w: %q", ErrInvalidKind, row.Kind)
	}
}

func unmarshalConfig(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, err.Error())
	}
	return nil
}
