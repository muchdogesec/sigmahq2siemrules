# sigmahq2siemrules

A GitHub Action-based uploader that automatically syncs Sigma detection rules from the [SigmaHQ repository](https://github.com/SigmaHQ/sigma) to the SIEMRULES API.

## Overview

This tool monitors changes to Sigma rule files (`.yml`/`.yaml`) in an external repository and automatically uploads them to a SIEMRULES instance. It tracks which rules have been processed and only uploads new or modified rules on subsequent runs.

## Features

- **Incremental Processing**: Tracks the last processed commit to avoid re-uploading unchanged rules
- **Concurrent Uploads**: Uses thread pools for efficient parallel file uploads
- **Job Monitoring**: Automatically monitors upload job status until completion
- **Detection Pack Integration**: Automatically maps rules to SigmaHQ detection packs by folder, creating missing packs when needed
- **GitHub Actions Integration**: Generates workflow summaries and artifacts
- **Error Handling**: Comprehensive error tracking and reporting
- **Deprecated Rule Filtering**: Option to skip rules in deprecated directories

## Environment Variables

### Required Variables (Action run)

| Variable | Description | Example |
|----------|-------------|---------|
| `SIEMRULES_BASE_URL` | Base URL for the SIEMRULES API | `https://api.siemrules.com` |
| `SIEMRULES_API_KEY` | API key for authenticating with SIEMRULES | `your-api-key-here` |

### Optional Variables (local run)

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_REPO_URL` | `https://github.com/SigmaHQ/sigma` | URL of the external repository to clone and process |
| `DETECTION_PACK_ID` | _(unset)_ | Optional fallback pack ID for rules that do not match known SigmaHQ folder mappings |
| `SIEMRULES_CSRF_TOKEN` | _(unset)_ | Optional CSRF token header used by some SIEMRULES deployments for detection-pack creation |
| `DETECTION_PACK_UUID_NAMESPACE` | `fa329051-43a6-5d2e-a3c0-bf3590ce2f41` | UUID namespace used to generate deterministic detection pack IDs |
| `PROCESS_DEPRECATED` | `false` | Whether to process rules in `deprecated` or `unsupported` directories. Set to `true`, `1`, `y`, or `yes` to enable |
| `MAX_WORKERS` | `10` | Number of concurrent workers for uploads and status checks |
| `STATUS_CHECK_INTERVAL` | `10` | Seconds to wait between job status checks |
| `MAX_STATUS_CHECKS` | `180` | Maximum number of status check rounds before timeout |

## Usage

### Command Line Arguments

```bash
python actions/uploader.py [OPTIONS]
```

**Options:**

- `--start-commit`: Starting commit SHA for diff comparison (defaults to last processed commit or empty tree)
- `--end-commit`: Ending commit SHA for diff comparison (defaults to HEAD)

### Example Usage

```bash
# Process all changes since last run (uses last_commit.txt)
python actions/uploader.py

# Process changes between specific commits
python actions/uploader.py --start-commit abc123 --end-commit def456

# Process from a specific commit to HEAD
python actions/uploader.py --start-commit abc123
```

### GitHub Actions Workflow

## How It Works

1. **Repository Cloning**: Clones the external Sigma repository
2. **Diff Calculation**: Compares the last processed commit with HEAD to find changed YAML files
3. **Filtering**: Optionally filters out rules in `deprecated` or `unsupported` directories
4. **Rule Upload**: Uploads each rule to SIEMRULES API (or modifies existing rules)
5. **Status Monitoring**: Polls job status until all jobs complete or timeout
6. **Detection Packs**: Finds/creates SigmaHQ detection packs and adds uploaded rules based on rule folder
7. **Artifacts**: Saves results to JSON files and generates GitHub workflow summary
8. **Commit Tracking**: Saves the current commit SHA for the next run

## Artifacts Generated

- `artifacts/succeeded_jobs.json` - List of successfully uploaded rules
- `artifacts/failed_jobs.json` - List of failed uploads with error details
- `artifacts/badges.json` - Badge data for display in README
- `artifacts/last_commit.txt` - Last processed commit SHA

## Dependencies

- `requests` - HTTP client for API calls
- `PyYAML` - YAML parsing and manipulation
- `gitpython` - Git repository operations

## Exit Codes

- `0` - Success (at least one successful upload OR no failures)
- `1` - Failure (no successful uploads AND at least one failure)
- `19` - Git/file retrieval error
