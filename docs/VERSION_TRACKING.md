# Version-Aware Supply Chain Detection

Watchtower now tracks **specific package versions** for supply chain vulnerabilities, not just package names. This dramatically reduces false positives by only flagging actually vulnerable versions.

## 🎯 How It Works

### Database Schema
Each IOC now includes a `version` field:
```sql
version VARCHAR(100) DEFAULT ''
```

**Unique Constraint**: `(value, source, version)`
- Same package can have multiple IOC records (one per version)
- Same version from different sources creates separate records

### OSV Data Extraction
The OSV provider extracts explicit version lists from vulnerability entries:

```json
{
  "id": "GHSA-xxxx-yyyy-zzzz",
  "affected": [{
    "package": {"name": "lodash"},
    "versions": ["4.17.0", "4.17.1", "4.17.2"]
  }]
}
```

**Result**: Creates 3 separate IOCs (one for each version)

### Query Formats

#### 1. Package Name Only
```bash
grpcurl -d '{"value": "lodash"}' localhost:50051 watchtower.Watchtower/SearchIOC
```
Returns **all vulnerable versions** of lodash

#### 2. Specific Version
```bash
grpcurl -d '{"value": "lodash@4.17.0"}' localhost:50051 watchtower.Watchtower/SearchIOC
```
Returns only if **that specific version** is vulnerable

#### 3. Scoped Packages (npm)
```bash
grpcurl -d '{"value": "@babel/core@7.0.0"}' localhost:50051 watchtower.Watchtower/SearchIOC
```
Correctly parses scoped package names with versions

## 📊 Database Behavior

### With Versions
```
value     | version  | source          | threat_type
----------|----------|-----------------|------------------------
lodash    | 4.17.0   | google-osv-npm  | supply_chain_malware
lodash    | 4.17.1   | google-osv-npm  | supply_chain_malware
lodash    | 4.17.2   | google-osv-npm  | supply_chain_malware
```

### Without Versions (Fallback)
If OSV doesn't provide explicit versions:
```
value     | version  | source          | threat_type
----------|----------|-----------------|------------------------
badpkg    | ''       | google-osv-npm  | supply_chain_malware
```
Empty version = **entire package flagged** (any version considered vulnerable)

## 🔍 Query Logic

### FindByValueAndVersion(value, version)
```sql
SELECT * FROM iocs
WHERE value = $1
  AND (version = $2 OR version = '')
```

**Logic**:
- Matches exact version specified
- **Also matches** empty version entries (wildcards)
- If `lodash@4.17.0` is queried and there's an entry with `(lodash, '')`, it matches!

### FindAllByValue(value)
```sql
SELECT * FROM iocs
WHERE value = $1
```

Returns **all versions** for the package (useful for SearchIOC)

## 🎨 Version Parsing

### Parse Function
```go
parsePackageVersion("lodash@4.17.0")
// Returns: ("lodash", "4.17.0")

parsePackageVersion("@babel/core@7.0.0")
// Returns: ("@babel/core", "7.0.0")

parsePackageVersion("lodash")
// Returns: ("lodash", "")
```

**Edge Cases Handled**:
- Scoped packages: `@org/pkg@1.0.0` → `(@org/pkg, 1.0.0)`
- No version: `lodash` → `(lodash, "")`
- Multiple `@` symbols: uses **last** `@` as separator

## 📈 Examples

### Example 1: Check Specific Version
```bash
# Query specific version
grpcurl -plaintext -d '{"value": "lodash@4.17.0"}' \
  localhost:50051 watchtower.Watchtower/SearchIOC
```

**Response** (if vulnerable):
```json
{
  "value": "lodash",
  "type": "package",
  "overall_score": 80,
  "sightings": [{
    "source": "google-osv-npm",
    "threat_type": "supply_chain_malware",
    "version": "4.17.0",
    "external_link": "https://osv.dev/vulnerability/GHSA-..."
  }]
}
```

### Example 2: Check All Versions
```bash
# Query package without version
grpcurl -plaintext -d '{"value": "lodash"}' \
  localhost:50051 watchtower.Watchtower/SearchIOC
```

**Response**:
```json
{
  "value": "lodash",
  "type": "package",
  "sightings": [
    {"version": "4.17.0", ...},
    {"version": "4.17.1", ...},
    {"version": "4.17.2", ...}
  ]
}
```

### Example 3: Safe Version
```bash
# Query a safe version
grpcurl -plaintext -d '{"value": "lodash@4.17.21"}' \
  localhost:50051 watchtower.Watchtower/SearchIOC
```

**Response** (if not vulnerable):
```json
{
  "value": "lodash",
  "sightings": []
}
```

## 🔧 Development

### Test Version Parsing
```go
// Add to internal/adapter/handler/grpc_test.go
func TestParsePackageVersion(t *testing.T) {
    tests := []struct{
        input string
        wantPkg string
        wantVer string
    }{
        {"lodash@4.17.0", "lodash", "4.17.0"},
        {"@babel/core@7.0.0", "@babel/core", "7.0.0"},
        {"lodash", "lodash", ""},
    }

    for _, tt := range tests {
        pkg, ver := parsePackageVersion(tt.input)
        if pkg != tt.wantPkg || ver != tt.wantVer {
            t.Errorf("parsePackageVersion(%q) = (%q, %q), want (%q, %q)",
                tt.input, pkg, ver, tt.wantPkg, tt.wantVer)
        }
    }
}
```

### Query Database Directly
```sql
-- See all versions of a package
SELECT value, version, source, threat_type
FROM iocs
WHERE value = 'lodash'
ORDER BY version;

-- Count IOCs by type
SELECT type, COUNT(*) as count,
       COUNT(DISTINCT value) as unique_packages
FROM iocs
GROUP BY type;

-- Find packages with multiple vulnerable versions
SELECT value, COUNT(*) as version_count
FROM iocs
WHERE type = 'package'
GROUP BY value
HAVING COUNT(*) > 1
ORDER BY version_count DESC
LIMIT 10;
```

## 🚀 Running with Version Support

### Full Setup
```bash
# Apply all migrations (including version column)
make db-migrate

# Run ingestion (extracts versions from OSV)
make ingestion-dev

# Check database for versioned IOCs
docker exec watchtower-postgres-1 psql -U admin -d watchtower \
  -c "SELECT value, version, source FROM iocs WHERE version != '' LIMIT 10;"
```

### Test Queries
```bash
# Start server
make run-dev

# Test version-specific query
grpcurl -plaintext -d '{"value": "some-package@1.0.0"}' \
  localhost:50051 watchtower.Watchtower/SearchIOC
```

## 📝 Migration Details

### Migration 002: Add Version Column
- Adds `version VARCHAR(100)` with default `''`
- Creates index on `(value, version)` for fast lookups
- Updates unique constraint from `(value, source)` to `(value, source, version)`
- Allows same package from same source but different versions

### Backward Compatibility
- ✅ Existing code works (empty version strings)
- ✅ Non-package IOCs (URLs, IPs) have `version = ''`
- ✅ Queries without version still work
- ✅ Database accepts both versioned and non-versioned IOCs

## 🎯 Future Enhancements

### Version Range Support
Currently tracks explicit versions only. Future: support ranges like:
- SemVer: `>=1.0.0 <2.0.0`
- npm: `^1.2.3` or `~1.2.3`
- Python: `>=1.0,<2.0`

### Version Comparison Logic
Implement per-ecosystem version comparison:
- npm/JavaScript: SemVer 2.0
- Python: PEP 440
- Maven: Maven version scheme
- Go: Module versioning

### API Enhancements
- New RPC: `CheckPackageVersion(name, version, ecosystem)`
- Response includes: nearest safe version, patch available, severity

## 📚 Related Files

- [internal/core/domain/ioc.go](internal/core/domain/ioc.go) - IOC struct with Version field
- [internal/adapter/provider/osv.go](internal/adapter/provider/osv.go) - Version extraction
- [internal/adapter/repository/postgres.go](internal/adapter/repository/postgres.go) - Version queries
- [internal/adapter/handler/grpc.go](internal/adapter/handler/grpc.go) - Version parsing
- [migrations/002_add_version_column.sql](migrations/002_add_version_column.sql) - Database schema

---

**Need help?** Run `make help` for all commands or see [MAKEFILE_GUIDE.md](MAKEFILE_GUIDE.md)
