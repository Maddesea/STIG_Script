# STIG Assessor: Extraction & Remediation Scenarios

> [!IMPORTANT]
> **✓ 100% Core Functionality Verified**
> The fix extraction, checking engines, and bulk remediation importer have been strictly vetted in connected and air-gapped runtimes.

## 1. The Big Picture: Automating the STIG Assessment Lifecycle
The standard DoD compliance lifecycle involves manually reading STIG configurations, executing commands, checking return values, and updating the CKL file. Our **Extraction** and **Remediation Injection** features streamline this directly from the source XCCDF files.

## 2. Scenario A: Automated Fix & Check Extraction
You have a massive benchmark, such as `U_RHEL_8_STIG_V1R10_Manual-xccdf.xml`. Instead of manually parsing the instructions for thousands of vulnerabilities, you can utilize the extraction engine.

### The Extraction Command
```bash
python -m stig_assessor --extract U_RHEL_8_STIG_V1R10.xml --outdir rhel_8_fixes
```

The engine leverages 12 distinct pattern recognizers to pull commands out of the raw text strings formatted by DISA. It automatically outputs **several distinct formats**:

| Output Format | File Generated | Role in Automation |
|---------------|----------------|--------------------|
| **Structured Data** | `fixes.json` | Contains a pure JSON object mappings of `V-ID -> Command` arrays. Easily digestible by your own pipelines. |
| **Linux Execution** | `remediate.sh` | A fully autonomous Bash script spanning all targets. When executed, it outputs a new JSON file determining if each fix was successful based on the command exit codes. |
| **Windows Target** | `Remediate.ps1` | A PowerShell script equipped with optional registry rollbacks and transcription logging. |
| **Orchestration** | `remediate.yml` | An Ansible playbook specifically created from the extracted shell commands for datacenter-wide rollout. |

> [!WARNING]
> **Dry-Run Mode:**
> Before blindly executing massive scripts to your golden images, use the `--script-dry-run` flag during extraction. This ensures the outputted scripts print what they *would* do without actually modifying the host.


## 3. Scenario B: Bulk Importer (The `--apply-results` Method)
After you execute `remediate.sh` or process scanner findings from third-party tools, you need to bring that data back into your assessment (the `.ckl` file).

### The Golden Results Format
The system expects a rigid JSON data-structure from scanners or your custom scripts. Example (`dummy_results.json`):
```json
{
    "results": [
        {
            "vid": "V-123456",
            "status": "NotAFinding",
            "finding_details": "Fix applied successfully. Output code: 0",
            "comments": "Automated pipeline on 2026-04-16"
        },
        {
            "vid": "V-234567",
            "status": "Open",
            "finding_details": "Permission Denied when modifying System32.",
            "comments": "Needs Tier-3 elevation."
        }
    ]
}
```

### Bulk Injecting Back into the CKL
Now, run the integration command to mutate a checklist intelligently based on the JSON results.
```bash
python -m stig_assessor --apply-results dummy_results.json --checklist SRV01_Unassessed.ckl --results-out SRV01_Completed.ckl
```

### Injection Behaviors & Safety Constraints
- **Automatic Status Handling:** The engine automatically maps your logical output. If a scan returned "fixed", it applies `NotAFinding`. If it failed, it maps to `Open`.
- **Details vs Comments:** Your imported text overrides the corresponding fields in the CKL so native STIG Viewer immediately recognizes the justification.
- **Smart Appending:** By default, the engine *prepends* new text to existing fields rather than forcefully wiping historical manual auditor comments. You can override this using `--details-mode overwrite`.

> [!TIP]
> **Advanced Edge-Case: Multiple Scanners**
> If your organization runs an SCAP scanner for generic compliance, but a secondary custom bash script for specific application checks, you can stack them!
> `stig-assessor --apply-results scap_results.json app_scan.json config_check.json --checklist target.ckl`
