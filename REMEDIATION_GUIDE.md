# Remediation JSON Generation Guide

## Overview

The `generate_remediation.py` script creates JSON files that can be fed to `STIG_Script.py` using the `--apply-results` command to bulk-update checklist statuses based on remediation results.

## Quick Start

### 1. Extract VIDs from an existing checklist

```bash
# Extract all Open findings and generate a template
python generate_remediation.py --from-ckl current.ckl --status Open --template-csv template.csv

# Edit template.csv with your results, then convert to JSON
python generate_remediation.py --from-csv template.csv --output remediation.json
```

### 2. Apply remediation results to checklist

```bash
python STIG_Script.py --apply-results remediation.json \
  --checklist current.ckl \
  --results-out updated.ckl
```

## Usage Examples

### Interactive Mode (Recommended for Beginners)

```bash
python generate_remediation.py
```

This launches an interactive wizard that guides you through the process.

### Single Result

```bash
# Mark V-123456 as successfully remediated
python generate_remediation.py --vid V-123456 --ok \
  --msg "Registry key updated" \
  --out "HKLM\Software\Policies\Microsoft set to 1" \
  --output single.json
```

### Batch Mode (Multiple VIDs)

```bash
# Mark multiple VIDs as remediated
python generate_remediation.py --batch V-123456,V-123457,V-123458 \
  --all-ok \
  --msg "Remediated via Group Policy" \
  --output batch.json
```

### From CSV File

Create a CSV file with this format:

```csv
vid,ok,msg,out,err
V-123456,true,Remediated,Registry updated,
V-123457,false,Failed,,Permission denied
V-123458,true,Remediated,Service disabled,
```

Then generate JSON:

```bash
python generate_remediation.py --from-csv results.csv --output remediation.json
```

### From CKL File (Extract VIDs)

```bash
# Extract all Open findings
python generate_remediation.py --from-ckl current.ckl --status Open --output remediation.json

# Extract all Not_Reviewed findings
python generate_remediation.py --from-ckl current.ckl --status Not_Reviewed --output remediation.json

# Extract ALL vulnerabilities
python generate_remediation.py --from-ckl current.ckl --output all_vulns.json
```

### Multi-System Format

When you have multiple systems with CSV results:

```bash
# Create CSV files for each system
# - server1.csv (contains results for SERVER-01)
# - server2.csv (contains results for SERVER-02)

python generate_remediation.py --multi-system server1.csv server2.csv \
  --output multi_system.json
```

## JSON Field Reference

Each remediation result has these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vid` | string | Yes | Vulnerability ID (e.g., "V-123456") |
| `ts` | string | Yes | ISO 8601 timestamp (auto-generated if omitted) |
| `ok` | boolean | Yes | `true` if remediation succeeded, `false` if failed |
| `msg` | string | No | Human-readable message (e.g., "Successfully remediated") |
| `out` | string | No | Command output or success details |
| `err` | string | No | Error message (typically used when `ok=false`) |

## Workflow Examples

### Scenario 1: Manual Remediation Tracking

1. **Extract open findings:**
   ```bash
   python generate_remediation.py --from-ckl current.ckl --status Open --template-csv findings.csv
   ```

2. **Edit findings.csv** - Update the `ok`, `msg`, `out`, and `err` columns based on your remediation efforts

3. **Generate JSON:**
   ```bash
   python generate_remediation.py --from-csv findings.csv --output remediation.json
   ```

4. **Apply to checklist:**
   ```bash
   python STIG_Script.py --apply-results remediation.json --checklist current.ckl --results-out updated.ckl
   ```

### Scenario 2: Automated Script Results

If you have an automated remediation script that outputs results:

1. **Have your script create a CSV file:**
   ```python
   import csv

   with open('auto_results.csv', 'w', newline='') as f:
       writer = csv.writer(f)
       writer.writerow(['vid', 'ok', 'msg', 'out', 'err'])

       # After each remediation attempt
       writer.writerow(['V-123456', 'true', 'Remediated', 'Service disabled', ''])
   ```

2. **Convert to JSON and apply:**
   ```bash
   python generate_remediation.py --from-csv auto_results.csv --output remediation.json
   python STIG_Script.py --apply-results remediation.json --checklist current.ckl --results-out updated.ckl
   ```

### Scenario 3: Multiple Servers (Bulk Operations)

1. **Create CSV for each server** (e.g., `server1.csv`, `server2.csv`)

2. **Generate multi-system JSON:**
   ```bash
   python generate_remediation.py --multi-system server*.csv --output all_servers.json
   ```

3. **Apply to each system's checklist individually:**
   ```bash
   # Extract results for specific system from JSON manually or use separate CSVs
   python generate_remediation.py --from-csv server1.csv --output server1.json
   python STIG_Script.py --apply-results server1.json --checklist server1.ckl --results-out server1_updated.ckl
   ```

## Advanced: Custom Metadata

For tracked deployments, use object format with metadata:

```bash
python generate_remediation.py --from-csv results.csv --format-type object --output remediation.json
```

This adds metadata like:
```json
{
  "meta": {
    "description": "Results from results.csv",
    "timestamp": "2025-11-16T12:00:00Z",
    "source": "results.csv"
  },
  "results": [...]
}
```

## Supported JSON Formats

The script supports all formats accepted by STIG_Script.py:

1. **Simple Array** (default) - Recommended for single-system
2. **Standard Object** (--format-type object) - With metadata
3. **Multi-System** (--multi-system) - Multiple systems in one file
4. **Alternative Keys** - Also supports `vulnerabilities`, `entries`, `res`, `findings` keys

View examples:
```bash
python generate_remediation.py --examples
python generate_remediation.py --examples --format simple_array
```

## Tips

1. **Always validate VIDs**: The script checks VID format (V-XXXXXX)
2. **Use timestamps**: Auto-generated timestamps track when remediation occurred
3. **CSV templates**: Use `--template-csv` to create a template you can edit manually
4. **Dry runs**: Generate JSON and inspect it before applying to checklists
5. **Backups**: STIG_Script.py automatically backs up checklists before applying results

## Troubleshooting

**Error: "Invalid VID format"**
- VIDs must start with "V-" followed by numbers (e.g., V-123456)

**Error: "No valid results in CSV"**
- Check CSV has header row: `vid,ok,msg,out,err`
- Ensure VIDs are valid format

**Error: "No vulnerabilities found in CKL"**
- Check status filter matches actual statuses in CKL
- Valid statuses: `Open`, `NotAFinding`, `Not_Applicable`, `Not_Reviewed`

**Empty output after applying results**
- Check that VIDs in JSON match VIDs in CKL file
- Use `--verbose` flag with STIG_Script.py to see detailed processing

## Integration with CI/CD

Example GitHub Actions workflow:

```yaml
- name: Run automated remediation
  run: |
    ./auto_remediate.sh > results.csv
    python generate_remediation.py --from-csv results.csv --output remediation.json
    python STIG_Script.py --apply-results remediation.json --checklist baseline.ckl --results-out updated.ckl
```

## Version History

- **v1.0.0** - Initial release
  - Interactive mode
  - CSV import/export
  - CKL VID extraction
  - Multi-system support
  - All STIG_Script.py format support

## See Also

- STIG_Script.py documentation
- CLAUDE.md (STIG Assessor documentation)
- Example CSV files in `examples/` directory
