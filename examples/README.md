# Example Files

This directory contains example CSV files demonstrating various remediation scenarios.

## Files

### example_remediation.csv
Complete example showing various result types:
- Successful remediations
- Failed remediations with error messages
- Different types of remediation actions

**Usage:**
```bash
python ../generate_remediation.py --from-csv example_remediation.csv --output example.json
```

### example_template.csv
Minimal template showing required CSV format.

**Usage:**
```bash
# Edit this file with your results, then:
python ../generate_remediation.py --from-csv example_template.csv --output my_results.json
```

### server1.csv & server2.csv
Multi-server example files.

**Usage:**
```bash
# Generate multi-system JSON
python ../generate_remediation.py --multi-system server1.csv server2.csv --output multi_server.json

# Or process individually
python ../generate_remediation.py --from-csv server1.csv --output server1.json
python ../generate_remediation.py --from-csv server2.csv --output server2.json
```

## Testing

Test the examples:

```bash
# Show JSON output without saving
python ../generate_remediation.py --from-csv example_remediation.csv

# Generate and inspect JSON
python ../generate_remediation.py --from-csv example_remediation.csv --output test.json
cat test.json | python -m json.tool

# Multi-system example
python ../generate_remediation.py --multi-system server*.csv --output multi_test.json
cat multi_test.json | python -m json.tool
```

## Creating Your Own CSV

Required columns:
- `vid` - Vulnerability ID (V-XXXXXX format)
- `ok` - Remediation success (true/false, yes/no, 1/0)
- `msg` - Human-readable message
- `out` - Command output or details
- `err` - Error message (if failed)

**Note:** The `ts` (timestamp) field is optional in CSV - it will be auto-generated during JSON creation.
