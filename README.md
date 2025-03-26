# SonarCloud Security Hotspots Exporter

A Python tool to export security hotspots from SonarCloud.io projects for analysis and reporting.

## Features

- List all projects in a SonarCloud organization
- Export security hotspots in JSON or CSV format
- Filter hotspots by status, security category, or severity
- Display summary statistics about security hotspots
- List available security categories for a project

## Requirements

- Python 3.6+
- `requests` library

## Installation

```bash
# Install dependencies
pip install requests
```

## Usage

Set your SonarCloud API token as an environment variable:

```bash
export SONARCLOUD_TOKEN=your_sonarcloud_token
```

Or pass it directly using the `--token` option.

### List projects in an organization

```bash
python sonarcloud_hotspots.py --organization your-org --list-projects
```

### Export security hotspots for a project

```bash
python sonarcloud_hotspots.py --organization your-org --project "Project Name" --key project-key --format csv --output hotspots.csv
```

### Display summary of security hotspots

```bash
python sonarcloud_hotspots.py --organization your-org --project "Project Name" --key project-key --summary
```

### Filter security hotspots

```bash
python sonarcloud_hotspots.py --organization your-org --project "Project Name" --key project-key --status TO_REVIEW --category auth --severity HIGH
```

### List security categories in a project

```bash
python sonarcloud_hotspots.py --organization your-org --project "Project Name" --key project-key --list-categories
```

## Arguments

- `--organization`, `-o`: SonarCloud organization key (required)
- `--project`, `-p`: Project name
- `--key`, `-k`: Project key in SonarCloud
- `--token`, `-t`: SonarCloud API token
- `--format`, `-f`: Output format (json or csv, default: json)
- `--output`: Output file (default: stdout)
- `--list-projects`, `-l`: List available projects in the organization
- `--list-categories`: List available security categories in the project
- `--status`: Filter by status (TO_REVIEW or REVIEWED)
- `--category`: Filter by security category (e.g., auth, xss)
- `--severity`: Filter by vulnerability probability/severity (HIGH, MEDIUM, LOW)
- `--summary`, `-s`: Display a summary of the results

## Written with Claude Code
