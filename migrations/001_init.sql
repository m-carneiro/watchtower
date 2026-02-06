-- Habilita extensão para gerar UUIDs (se necessário, mas Postgres 15 já tem nativo)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    value TEXT NOT NULL,
    type VARCHAR(50) NOT NULL,
    source VARCHAR(100) NOT NULL,
    threat_type VARCHAR(100),
    tags TEXT[],
    first_seen TIMESTAMP WITH TIME ZONE,
    date_ingested TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Impede duplicatas do mesmo feed
    CONSTRAINT unique_ioc_source UNIQUE (value, source)
);

-- Cria índice para a busca ficar rápida
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);