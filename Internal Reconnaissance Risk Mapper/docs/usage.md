# Internal Reconnaissance Risk Mapper - Usage Guide

## Overview

Internal Reconnaissance Risk Mapper is a defensive command-line tool for identifying internally exposed services and generating basic risk assessments.

It accepts a single IP address or a CIDR subnet, scans configured TCP ports, collects basic banners, classifies discovered services, calculates risk, and saves a JSON report.

This tool must only be used in environments where you have explicit authorization.

---

## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- Python packages listed in `requirements.txt`

---

## Installation

Open a terminal inside the project directory.

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Verify that `pytest` is available:

```bash
python -m pytest --version
```

---

## Basic Usage

Scan a single host:

```bash
python irmapper.py --target 127.0.0.1
```

Scan a CIDR subnet:

```bash
python irmapper.py --target 192.168.1.0/24
```

Specify a shorter timeout:

```bash
python irmapper.py --target 192.168.1.0/24 --timeout 0.5
```

Specify the number of scanning threads:

```bash
python irmapper.py --target 192.168.1.0/24 --threads 50
```

Specify an output report path:

```bash
python irmapper.py --target 192.168.1.0/24 --output reports/internal_scan.json
```

Use custom configuration files:

```bash
python irmapper.py --target 192.168.1.0/24 --ports config/default_ports.yml --risk-rules config/risk_rules.yml
```

---

## Command-Line Arguments

| Argument       | Required | Default                    | Description                                |
| -------------- | -------: | -------------------------- | ------------------------------------------ |
| `--target`     |      Yes | None                       | Target IP address or CIDR subnet           |
| `--ports`      |       No | `config/default_ports.yml` | Path to the ports configuration file       |
| `--risk-rules` |       No | `config/risk_rules.yml`    | Path to the risk rules configuration file  |
| `--output`     |       No | `reports/report.json`      | Path where the JSON report will be saved   |
| `--format`     |       No | `json`                     | Report format. Currently JSON is supported |
| `--threads`    |       No | `50`                       | Number of concurrent scanning workers      |
| `--timeout`    |       No | `1.0`                      | TCP connection timeout in seconds          |

---

## Example Scan

Command:

```bash
python irmapper.py --target 192.168.2.0/24 --timeout 1
```

Example terminal output:

```text
Internal Reconnaissance Risk Mapper
-----------------------------------
Target: 192.168.2.0/24
Parsed hosts: 254
Ports config: config/default_ports.yml
Loaded ports: 10
Risk rules config: config/risk_rules.yml
Output: reports/report.json
Format: json
Threads: 50
Timeout: 1.0

[+] Starting TCP port scan...

[+] Collecting basic service banners...
[+] Classifying discovered services...
[+] Calculating risk scores...
[+] Scan completed.
[+] Hosts scanned: 254
[+] Hosts with open ports: 5
[+] JSON report saved to: reports/report.json
```

---

## Example Finding

Example output for a host with SMB exposed:

```text
Host: 192.168.2.3
Risk: Low (25/100)
  - 445/tcp SMB (file_sharing, internal_lateral_movement_risk)
    sensitive: yes

Findings:
  - [High] SMB file sharing exposure on 445/tcp
    recommendation: Restrict SMB access by subnet, disable SMBv1, enforce least privilege, and audit shared folders.
```

---

## Output

The default report is saved to:

```text
reports/report.json
```

The JSON report includes:

- tool name and version
- generation timestamp
- target
- configuration paths
- summary
- host results
- open ports
- banners
- exposure types
- risk scores
- findings
- recommendations

---

## Configuration

### Ports Configuration

Default file:

```text
config/default_ports.yml
```

Example:

```yaml
ports:
  - port: 445
    service: SMB
    category: file_sharing
```

This file controls which TCP ports the tool scans.

---

### Risk Rules Configuration

Default file:

```text
config/risk_rules.yml
```

Example:

```yaml
risk_rules:
  SMB:
    severity: High
    score: 25
    finding: SMB file sharing exposure
    recommendation: Restrict SMB access by subnet, disable SMBv1, enforce least privilege, and audit shared folders.
```

This file controls:

- risk score
- finding severity
- finding title
- remediation recommendation

---

## Risk Scoring

The host risk level is calculated from the total score of exposed services.

```text
0-30     Low
31-69    Medium
70-100   High
```

A finding can have high severity even if the total host risk is low.

Example:

```text
SMB finding severity: High
Host total risk score: 25
Host risk level: Low
```

This means the specific exposed service is important, but the overall host score has not crossed the medium threshold.

---

## Running Tests

Run all tests:

```bash
python -m pytest
```

Expected result:

```text
19 passed
```

Run a specific test file:

```bash
python -m pytest tests/test_target_parser.py
```

Run risk engine tests only:

```bash
python -m pytest tests/test_risk_engine.py
```

Run service classifier tests only:

```bash
python -m pytest tests/test_service_classifier.py
```

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'yaml'`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Or install PyYAML directly:

```bash
python -m pip install pyyaml
```

---

### `No module named pytest`

Install pytest:

```bash
python -m pip install pytest
```

Then run:

```bash
python -m pytest
```

---

### `Config file not found`

Make sure these files exist:

```text
config/default_ports.yml
config/risk_rules.yml
```

Also make sure the file extension is `.yml`, not `.yaml`, unless the CLI path is changed.

---

### No open ports found

Possible reasons:

- The target subnet is not the correct local subnet.
- Hosts are offline.
- Firewalls are blocking the scanned ports.
- The configured port list is limited.
- Timeout is too low.

Try checking your local subnet with:

```bash
ipconfig
```

Then scan the correct subnet, for example:

```bash
python irmapper.py --target 192.168.2.0/24 --timeout 1
```

---

## Security Boundaries

This tool is designed for defensive and authorized use only.

It does not:

- exploit vulnerabilities
- attempt authentication
- perform brute force
- modify systems
- exfiltrate data

It only performs basic TCP connectivity checks and minimal banner collection.

Use only with authorization.
