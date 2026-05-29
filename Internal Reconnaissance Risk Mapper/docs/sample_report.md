# Internal Reconnaissance Risk Mapper - Sample Report

## Report Overview

This document shows an example output from the Internal Reconnaissance Risk Mapper.

The purpose of this sample report is to demonstrate how the tool presents internally exposed services, risk scores, findings, and remediation recommendations.

This is a sample report for documentation and portfolio purposes. The IP addresses and results should be treated as example data.

---

## Scan Metadata

| Field                 | Value                               |
| --------------------- | ----------------------------------- |
| Tool                  | Internal Reconnaissance Risk Mapper |
| Version               | 0.1.0                               |
| Target                | `192.168.2.0/24`                    |
| Hosts scanned         | 254                                 |
| Hosts with open ports | 5                                   |
| Total findings        | 7                                   |
| Output format         | JSON                                |
| Report path           | `reports/report.json`               |

---

## Executive Summary

The scan identified **5 hosts** with exposed TCP services inside the target subnet.

The most relevant exposure types were:

- Web service exposure
- HTTPS web service exposure
- SMB file sharing exposure
- Internal lateral movement risk

The most important recurring finding was **SMB file sharing exposure**, which was detected on multiple hosts. SMB exposure can increase internal lateral movement risk if share permissions, authentication, or network segmentation are weak.

---

## Risk Summary

| Risk Level | Count |
| ---------- | ----: |
| High       |     0 |
| Medium     |     1 |
| Low        |     4 |

---

## Top Risk Hosts

| Rank | Host          | Risk Level | Risk Score | Main Concern                 |
| ---: | ------------- | ---------- | ---------: | ---------------------------- |
|    1 | `192.168.2.1` | Medium     |     35/100 | HTTP, HTTPS, and SMB exposed |
|    2 | `192.168.2.3` | Low        |     25/100 | SMB exposed                  |
|    3 | `192.168.2.7` | Low        |     25/100 | SMB exposed                  |
|    4 | `192.168.2.2` | Low        |      5/100 | HTTP exposed                 |
|    5 | `192.168.2.4` | Low        |      5/100 | HTTP exposed                 |

---

## Host Findings

### Host: `192.168.2.1`

**Risk:** Medium
**Score:** 35/100

#### Open Services

|    Port | Service | Category     | Exposure Type                  | Sensitive |
| ------: | ------- | ------------ | ------------------------------ | --------- |
|  80/tcp | HTTP    | web          | web_service_exposure           | No        |
| 443/tcp | HTTPS   | web          | web_service_exposure           | No        |
| 445/tcp | SMB     | file_sharing | internal_lateral_movement_risk | Yes       |

#### Banners

```text
80/tcp  HTTP/1.1 400 Bad Request Accept-Ranges: bytes Connection: close X-Frame-Options: SAMEORIGIN
443/tcp HTTP/1.1 400 Bad Request Accept-Ranges: bytes Connection: close X-Frame-Options: SAMEORIGIN
```

#### Findings

##### [Low] Web service exposure on 80/tcp

**Description:**
HTTP is reachable from the scanned network.

**Recommendation:**
Verify that the web service is expected, patched, and does not expose sensitive internal information.

##### [Low] HTTPS web service exposure on 443/tcp

**Description:**
HTTPS is reachable from the scanned network.

**Recommendation:**
Verify TLS configuration, authentication, and whether the service should be reachable from the scanned network.

##### [High] SMB file sharing exposure on 445/tcp

**Description:**
SMB is reachable from the scanned network.

**Recommendation:**
Restrict SMB access by subnet, disable SMBv1, enforce least privilege, and audit shared folders.

---

### Host: `192.168.2.2`

**Risk:** Low
**Score:** 5/100

#### Open Services

|   Port | Service | Category | Exposure Type        | Sensitive |
| -----: | ------- | -------- | -------------------- | --------- |
| 80/tcp | HTTP    | web      | web_service_exposure | No        |

#### Banner

```text
HTTP/1.1 405 Method Not Allowed Content-Type: text/html;charset=UTF-8 Content-Length: 0 Connection: close Cache-control: no-cache
```

#### Findings

##### [Low] Web service exposure on 80/tcp

**Description:**
HTTP is reachable from the scanned network.

**Recommendation:**
Verify that the web service is expected, patched, and does not expose sensitive internal information.

---

### Host: `192.168.2.3`

**Risk:** Low
**Score:** 25/100

#### Open Services

|    Port | Service | Category     | Exposure Type                  | Sensitive |
| ------: | ------- | ------------ | ------------------------------ | --------- |
| 445/tcp | SMB     | file_sharing | internal_lateral_movement_risk | Yes       |

#### Findings

##### [High] SMB file sharing exposure on 445/tcp

**Description:**
SMB is reachable from the scanned network.

**Recommendation:**
Restrict SMB access by subnet, disable SMBv1, enforce least privilege, and audit shared folders.

---

### Host: `192.168.2.4`

**Risk:** Low
**Score:** 5/100

#### Open Services

|   Port | Service | Category | Exposure Type        | Sensitive |
| -----: | ------- | -------- | -------------------- | --------- |
| 80/tcp | HTTP    | web      | web_service_exposure | No        |

#### Banner

```text
HTTP/1.1 200 OK Server: SHIP 2.0 Content-Length: 49 Content-Type: text/html
```

#### Findings

##### [Low] Web service exposure on 80/tcp

**Description:**
HTTP is reachable from the scanned network.

**Recommendation:**
Verify that the web service is expected, patched, and does not expose sensitive internal information.

---

### Host: `192.168.2.7`

**Risk:** Low
**Score:** 25/100

#### Open Services

|    Port | Service | Category     | Exposure Type                  | Sensitive |
| ------: | ------- | ------------ | ------------------------------ | --------- |
| 445/tcp | SMB     | file_sharing | internal_lateral_movement_risk | Yes       |

#### Findings

##### [High] SMB file sharing exposure on 445/tcp

**Description:**
SMB is reachable from the scanned network.

**Recommendation:**
Restrict SMB access by subnet, disable SMBv1, enforce least privilege, and audit shared folders.

---

## Remediation Priorities

### Priority 1: Review SMB Exposure

SMB was found on multiple hosts. This should be reviewed first because SMB can contribute to internal lateral movement risk.

Recommended actions:

- Restrict SMB access by subnet.
- Disable SMBv1.
- Enforce least privilege on shared folders.
- Audit share permissions.
- Monitor SMB authentication and file access events.

---

### Priority 2: Review Internal Web Services

Several HTTP/HTTPS services were reachable from the scanned network.

Recommended actions:

- Confirm that each web service is expected.
- Ensure services are patched.
- Restrict administrative interfaces.
- Require authentication where appropriate.
- Avoid exposing sensitive internal information in headers or pages.

---

### Priority 3: Improve Network Segmentation

If these services do not need to be reachable from all internal hosts, network segmentation should be improved.

Recommended actions:

- Limit access to administrative services.
- Separate user, server, guest, and management networks.
- Apply firewall rules based on business need.
- Monitor unexpected internal connections.

---

## Notes

A host can have a **Low** overall risk score while still containing a **High severity finding**.

Example:

```text
SMB finding severity: High
Host risk score: 25/100
Host risk level: Low
```

This means the specific service exposure is important, but the total score for the host has not crossed the Medium threshold.

---

## Security Boundaries

This tool does not exploit vulnerabilities, attempt authentication, perform brute force, modify target systems, or exfiltrate data.

It only performs:

- Basic TCP connectivity checks
- Minimal banner collection
- Local risk scoring based on configuration
- Report generation

Use only in authorized environments.
