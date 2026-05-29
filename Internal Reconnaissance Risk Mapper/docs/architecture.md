# Internal Reconnaissance Risk Mapper - Architecture

## Component Responsibilities

### 1. CLI

**File:**

```text
irmapper_core/cli.py
```

The CLI is the main coordinator of the application.

**Responsibilities:**

- Read command-line arguments.
- Accept target IP or CIDR subnet.
- Load configuration files.
- Start scanning.
- Trigger banner grabbing.
- Trigger service classification.
- Trigger risk scoring.
- Generate reports.

**Example command:**

```bash
python irmapper.py --target 192.168.2.0/24 --timeout 1
```

---

### 2. Target Parser

**File:**

```text
irmapper_core/target_parser.py
```

The target parser converts user input into a list of IP addresses.

**Supported inputs:**

```text
127.0.0.1
192.168.2.0/24
192.168.1.10
```

**Responsibilities:**

- Validate IP addresses.
- Validate CIDR subnets.
- Convert CIDR subnets into usable host IPs.
- Reject invalid targets.

**Example:**

```python
parse_targets("192.168.1.0/30")
```

**Output:**

```python
["192.168.1.1", "192.168.1.2"]
```

---

### 3. Config Loader

**File:**

```text
irmapper_core/utils.py
```

The config loader reads YAML configuration files.

**Configuration files:**

```text
config/default_ports.yml
config/risk_rules.yml
```

**Responsibilities:**

- Load YAML files.
- Validate that YAML content is structured as a dictionary.
- Provide reusable helper functions.

---

### 4. Scanner

**File:**

```text
irmapper_core/scanner.py
```

The scanner performs TCP connection checks against configured ports.

**Responsibilities:**

- Accept a list of hosts.
- Accept a list of ports.
- Check whether each TCP port is open.
- Return raw scan results.
- Use threads for faster scanning.

The scanner does not calculate risk and does not classify services.

**Example output:**

```json
{
  "host": "192.168.2.1",
  "open_ports": [
    {
      "port": 80,
      "service": "HTTP",
      "category": "web"
    },
    {
      "port": 445,
      "service": "SMB",
      "category": "file_sharing"
    }
  ]
}
```

---

### 5. Banner Grabber

**File:**

```text
irmapper_core/banner_grabber.py
```

The banner grabber collects minimal service information from supported services.

**Supported services:**

- SSH
- HTTP
- HTTPS
- HTTP-Alt
- HTTPS-Alt

**Responsibilities:**

- Read SSH banners.
- Send minimal HTTP/HTTPS HEAD requests.
- Collect response headers.
- Avoid authentication.
- Avoid brute force.
- Avoid exploitation.

**Example banner:**

```text
HTTP/1.1 200 OK Server: nginx
```

---

### 6. Service Classifier

**File:**

```text
irmapper_core/service_classifier.py
```

The service classifier enriches discovered services with security-relevant metadata.

**Responsibilities:**

- Map service categories to exposure types.
- Identify sensitive services.
- Identify possible admin interfaces.

**Example input:**

```json
{
  "port": 445,
  "service": "SMB",
  "category": "file_sharing"
}
```

**Example output:**

```json
{
  "port": 445,
  "service": "SMB",
  "category": "file_sharing",
  "exposure_type": "internal_lateral_movement_risk",
  "is_sensitive": true,
  "is_admin_interface": false
}
```

---

### 7. Risk Engine

**File:**

```text
irmapper_core/risk_engine.py
```

The risk engine calculates risk scores and findings.

**Responsibilities:**

- Read service risk rules.
- Assign scores to exposed services.
- Generate findings.
- Generate recommendations.
- Calculate host risk level.

**Risk level scale:**

```text
0-30     Low
31-69    Medium
70-100   High
```

**Example:**

```json
{
  "risk_score": 35,
  "risk_level": "Medium",
  "findings": [
    {
      "title": "SMB file sharing exposure",
      "severity": "High",
      "recommendation": "Restrict SMB access by subnet."
    }
  ]
}
```

---

### 8. Reporter

**File:**

```text
irmapper_core/reporter.py
```

The reporter creates structured output from the final scan results.

**Current output:**

```text
reports/report.json
```

**Responsibilities:**

- Build report summary.
- Build full JSON report.
- Save report files.
- Print terminal summary.

**Future output formats:**

- HTML report
- Markdown report
- CSV export

---

## Data Flow

The tool processes data in this order:

```text
User target
  ↓
List of IP addresses
  ↓
Raw open ports
  ↓
Open ports with banners
  ↓
Classified services
  ↓
Risk-scored host results
  ↓
JSON report
```

---

## Configuration Files

### `default_ports.yml`

Defines which ports should be scanned.

**Example:**

```yaml
ports:
  - port: 445
    service: SMB
    category: file_sharing
```

---

### `risk_rules.yml`

Defines how each discovered service should be scored.

**Example:**

```yaml
risk_rules:
  SMB:
    severity: High
    score: 25
    finding: SMB file sharing exposure
    recommendation: Restrict SMB access by subnet.
```

---

## Testing

The project includes unit tests under:

```text
tests/
```

**Current test files:**

```text
tests/test_target_parser.py
tests/test_risk_engine.py
tests/test_service_classifier.py
```

Run tests with:

```bash
python -m pytest
```

Expected result:

```text
19 passed
```

---

## Security Boundaries

This tool is designed for defensive and authorized use only.

It does not:

- Exploit vulnerabilities.
- Attempt authentication.
- Perform brute force.
- Modify target systems.
- Exfiltrate data.

It only performs basic TCP connectivity checks and minimal banner collection.
