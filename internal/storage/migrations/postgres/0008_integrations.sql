-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- integrations — outbound sinks for audit events (and, eventually, metrics).
-- PRD: FR-C.84..89.
--
-- v0.1 supported kinds (CHECK enforces them):
--   webhook  — generic JSON POST
--   splunk   — Splunk HEC (HTTPS POST to /services/collector)
--   sentinel — Microsoft Sentinel Log Analytics Data Collector API
--   elastic  — Elasticsearch _bulk ingest
--   syslog   — RFC 5424 over UDP/TCP
--
-- config_json carries the kind-specific knobs (URL, token, workspace_id,
-- shared_key, index, etc.). The application layer validates the shape per
-- kind before persisting; we keep this as opaque JSON in the schema so a
-- future kind can land without a migration.
--
-- filters_json: a JSON object documenting the prefixes / event_types this
-- sink should receive. {"event_types": ["admin.", "request.rate_limited"]}.
-- An empty/missing filter forwards everything.
-- ---------------------------------------------------------------------------
CREATE TABLE integrations (
    id                    BIGSERIAL    PRIMARY KEY,
    name                  TEXT         NOT NULL UNIQUE,
    kind                  TEXT         NOT NULL CHECK (kind IN ('webhook','splunk','sentinel','elastic','syslog')),
    enabled               BOOLEAN      NOT NULL DEFAULT TRUE,
    config_json           TEXT         NOT NULL DEFAULT '{}',
    filters_json          TEXT         NOT NULL DEFAULT '{}',
    created_by_admin_id   BIGINT       REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX integrations_enabled_idx ON integrations (enabled) WHERE enabled = TRUE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS integrations;
-- +goose StatementEnd
