-- Migration: Add version column for package version tracking
-- This enables version-specific vulnerability detection for supply chain threats

-- Add version column to iocs table
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS version VARCHAR(100) DEFAULT '';

-- Create index for version queries (package name + version lookups)
CREATE INDEX IF NOT EXISTS idx_iocs_value_version ON iocs(value, version);

-- Update unique constraint to include version
-- Drop old constraint
ALTER TABLE iocs DROP CONSTRAINT IF EXISTS unique_ioc_source;

-- Add new constraint: (value, source, version) must be unique
-- This allows same package from same source but different versions
ALTER TABLE iocs ADD CONSTRAINT unique_ioc_source_version UNIQUE (value, source, version);

-- Add comment for documentation
COMMENT ON COLUMN iocs.version IS 'Package version for supply chain IOCs (e.g., "4.17.0"). Empty string for non-versioned IOCs (URLs, IPs, etc).';
